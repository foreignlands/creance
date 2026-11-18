//! A6 DNS wire 炸弹矩阵：对生产 dnsmsg.rs 拷贝驱动 unpack/pack。
//! 变体：保留前缀标签、指针环/炸弹、qdcount 边界、非 UTF8、rdlen 越界。

#[path = "dnsmsg_copy.rs"]
mod dnsmsg;
use dnsmsg::Message;

fn header(qd: u16, an: u16) -> Vec<u8> {
    let mut b = vec![0u8; 12];
    b[2] = 0x80; // response
    b[4..6].copy_from_slice(&qd.to_be_bytes());
    b[6..8].copy_from_slice(&an.to_be_bytes());
    b
}

fn case(name: &str, wire: Vec<u8>, expect_ok: bool) {
    match Message::unpack(&wire) {
        Ok(m) => {
            let names: Vec<String> = m.questions.iter().map(|q| q.name.clone()).collect();
            let anames: Vec<String> = m.answers.iter().map(|a| a.name.clone()).collect();
            let lens: Vec<usize> = m.answers.iter().map(|a| a.data.len()).collect();
            println!(
                "[UNPACK-OK] {name} qnames={names:?} anames={anames:?} rdlen={lens:?} qd={} an={}",
                m.questions.len(),
                m.answers.len()
            );
            if !expect_ok {
                println!("   ^^^ 预期拒绝，实际接受 —— 候选发现");
            }
        }
        Err(e) => println!("[UNPACK-ERR] {name} :: {e}{}", if expect_ok { "  ^^^ 预期接受，实际拒绝" } else { "" }),
    }
}

fn main() {
    // 1. RFC 保留前缀 0x80（EDNS bitstring）：128 字节"标签"——miekg/dns 会拒绝
    let mut w = header(1, 0);
    w.push(0x80);
    w.extend_from_slice(&[0x41u8; 128]);
    w.push(0);
    w.extend_from_slice(&[0, 1, 0, 1]);
    case("prefix-0x80-label-128", w, false);

    // 2. 保留前缀 0x40：64 字节标签
    let mut w = header(1, 0);
    w.push(0x40);
    w.extend_from_slice(&[0x41u8; 64]);
    w.push(0);
    w.extend_from_slice(&[0, 1, 0, 1]);
    case("prefix-0x40-label-64", w, false);

    // 3. 合法 63 字节标签边界
    let mut w = header(1, 0);
    w.push(63);
    w.extend_from_slice(&[0x41u8; 63]);
    w.push(0);
    w.extend_from_slice(&[0, 1, 0, 1]);
    case("label-63-legal", w, true);

    // 4. 指针环 A->B->A（12 处）
    let mut w = header(1, 0);
    w.extend_from_slice(&[0xc0, 0x0e]); // 12: 指向 14
    w.extend_from_slice(&[0xc0, 0x0c]); // 14: 指回 12
    w.extend_from_slice(&[0, 1, 0, 1]);
    case("pointer-loop-ab", w, false);

    // 5. 128 层合法指针链（label + 指回上一个 label 的链）
    let mut w = header(1, 0);
    let name_at = w.len();
    w.push(1);
    w.push(b'a');
    w.push(0xc0); // 指向 name_at —— 自身 label+pointer 循环但 jumps 恰好 128 内?
    w.extend_from_slice(&(name_at as u16).to_be_bytes());
    // 上面的环会 128 跳后拒绝 —— 单独测非环 128 层不现实,改测:
    // 64 层展开(每层 label+自指针?)不可行——环就是环。测 2 层互指已在 4 覆盖。
    w.extend_from_slice(&[0, 1, 0, 1]);
    case("pointer-self-128-bounded", w, false);

    // 6. qdcount=65535 但 body 只有头
    let w = header(65535, 0);
    case("qd-65535-empty", w, false);

    // 7. question name 非 UTF8 字节
    let mut w = header(1, 0);
    w.push(3);
    w.extend_from_slice(&[0xff, 0xfe, 0x80]);
    w.push(0);
    w.extend_from_slice(&[0, 1, 0, 1]);
    case("non-utf8-label", w, true);

    // 8. rdlen 越界（声明 0xFFFF，实际 2 字节）
    let mut w = header(0, 1);
    w.push(0);
    w.extend_from_slice(&[0, 1, 0, 1, 0, 0, 0, 60, 0xff, 0xff]);
    w.extend_from_slice(&[0x41, 0x42]);
    case("rdlen-overflow", w, false);

    // 9. qd=1 an=65535
    let mut w = header(1, 65535);
    w.push(0);
    w.extend_from_slice(&[0, 1, 0, 1]);
    w.push(0);
    w.extend_from_slice(&[0, 1, 0, 1, 0, 0, 0, 60, 0, 4]);
    w.extend_from_slice(&[1, 2, 3, 4]);
    case("an-65535-declared", w, false);

    // 10. 压缩指针指向 header（12）——把 header 字节当标签解析
    let mut w = header(1, 0);
    let p_at = w.len();
    w.extend_from_slice(&[0xc0, 0x0c]);
    w.extend_from_slice(&[0, 1, 0, 1]);
    // header[12] 在此 case 里越界( buf 12 字节头 + 指针)——target=12 < len ✓
    // 12 处字节 = 0xc0 → 指针!→ 指向 0x0c*256+0x0c? no: buf[12]=0xc0, buf[13]=0x0c? target=((0xc0&0x3f)<<8)|0x0c = 12 → 环 → jumps 拒绝
    let _ = p_at;
    case("pointer-to-header", w, false);

    // 11. pack 端：answer data > 65535 截断地雷（len as u16）
    let r = Message::reply(
        &Message::query(1, "x", 1),
        0,
        vec![dnsmsg::Resource {
            name: "x".into(),
            rtype: 1,
            class: 1,
            ttl: 1,
            data: vec![0u8; 65536],
        }],
    );
    match r.pack() {
        Ok(packed) => {
            // rdlen 字段位置:头12+name(2:0x00)+4(type+class)+4(ttl)+2 → 22..24
            let rdlen = u16::from_be_bytes([packed[20], packed[21]]);
            println!("[PACK] data=65536 -> rdlen_field={rdlen} ({} bytes total wire)", packed.len());
            println!("   ^^^ data>65535 被 as u16 截断（当前调用方恒小,潜在地雷）");
        }
        Err(e) => println!("[PACK-ERR] {e}"),
    }
}
