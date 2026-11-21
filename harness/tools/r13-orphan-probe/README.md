# r13-orphan-probe — F-056 复现探针：reap_orphan_cores 的 pgrep ERE 元字符面

`crates/creance-proxy/src/service.rs:208` 把 profile 目录路径未经转义地拼进
`pgrep -f` 的 ERE 签名 `"{d}/mihomo -d {d}"`。本探针用最小假核心（pause 二进制，
argv 形状与真 mihomo 一致）证明三个方向：

- A 正控（无元字符目录）：收割网正常工作 → 证明探针鉴别力；
- B 漏匹配（目录含 `+`）：自己的孤儿不被收割 → 下次 start "端口被占" 楔死；
- C 过匹配（另一目录名恰好落入 `a+b` 的 ERE）：**别的 profile 的孤儿被本
  profile 的 stop 杀掉** → 跨目录误杀；
- D 畸形（目录含未闭合 `(`）：pgrep regcomp 失败 → 静默 no-op（无声漏匹配）。

驱动脚本：`probe.sh`（假核心 C 源：`fakecore.c`）。产物全部在 /tmp/r13-ere/。
