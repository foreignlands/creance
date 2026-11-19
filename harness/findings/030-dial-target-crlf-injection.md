# FINDING-030: Egress::dial 目标 addr 的 CRLF 可注入 CONNECT 请求头（潜伏 API 硬化，生产不可达）

- **编号**: 030
- **严重度**: S5（API 加固；当前生产路径无攻击者可控的原始 dial 目标）
- **攻击面**: B1/B2（egress.rs `dial`/`http_connect`），harness/tools/b1-socks5-probe 变体 M2
- **发现时间**: 2026-11-19T09:40Z
- **发现者会话**: R4 (s01)
- **状态**: 待修复

## 复现（必须）

工具：`harness/tools/b1-socks5-probe/`（cargo run --release，变体 M2）。
恶意 HTTP 代理（回环 TcpListener）+ 真实 egress 客户端：

```rust
let egress = Egress::new("http://127.0.0.1:{p}", "https://192.0.2.53/dns-query")?;
egress.dial_deadline("1.2.3.4\r\nX-Injected: yes\r\nHost: x:99", deadline)?;
```

- **期望**: `split_addr`/`dial` 拒绝含 CR/LF（及一般控制字符）的目标
  host——目标将逐字拼进 `CONNECT {target} HTTP/1.1` 请求（egress.rs:391-392）。
- **实际**（实测输出）:
  ```
  HOLE   M2 crlf-numeric-port: header injection in CONNECT request:
  CONNECT 1.2.3.4
  X-Injected: yes
  Host: x:99 HTTP/1.1
  ...
  HOLE?  M2 crlf-numeric-port: dial SUCCEEDED
  ```
  注入成立的形状：**最后一个冒号之后必须是数字端口**（变体 M 的尾缀 CRLF
  使端口段 `yes` 非数字而被 split_addr 拒绝——拒绝原因与注入无关，纯巧
  合）。`join_addr`/`http_connect` 对 host 不做任何字符白名单。

## 根因猜测

- `crates/creance-net/src/egress.rs:391-392`（`http_connect`）与
  `split_addr`/`join_addr`：目标 host 无 CRLF/控制字符过滤。
- 生产不可达论证：唯一带外部 URL 的调用方 `request_bounded`
  （egress.rs:685+）取 host 于 `url::Url::parse` 的 WHATWG 规范化输出
  （特殊 scheme 的 host 中 C0 控制字符被剥离/编码）；`creance check` 与
  workbench /api/check 用常量 CHECK_URL。`Egress::dial` 是公开 API，未来
  调用方（如 guest 侧任意域名转发）若直传原始字符串即打开注入面。

## 未验证想法

1. SOCKS5 路径同一目标（atyp 0x03 domain）接受任意字节作为 domain——
   无注入语义（二进制长度前缀），但畸形 domain 对核心的行为未测（mihomo
   侧的容错属上游面）。
2. auth 子协商应答的版本字节（status[0]）不校验（同工具变体 E，实测接
   受 `01 00`）——Go x/net proxy/socks5.go 疑似同样只查 status[1]（本地
   无 vendor 无法实证），按平价未定处理，无安全影响。

## 建议修复方向（供第二天的人参考，非结论）

`split_addr` 或 `dial_deadline` 入口对 host 增加 C0 控制字符（至少
CR/LF）白名单拒绝，错误文案与既有"无效目标"族一致。
