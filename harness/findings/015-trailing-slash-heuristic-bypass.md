# FINDING-015: 004 尾斜杠启发式可被尾随空白/反斜杠绕过（4 变体误放行）——WHATWG 解析器 strip C0/space 与原始串 ends_with('/') 的错位

- **编号**: 015
- **严重度**: S5（配置卫生检查的边角漂移；proxy_url 的 path 从不用于拨号，无实质危害；night-03 修复 8d862d4 引入的回归）
- **攻击面**: R2 回归审查 → 004（8d862d4）
- **发现时间**: 2026-11-19T01:44:47Z
- **发现者会话**: r2-s01
- **状态**: 待修复

## 复现（必须）

探针：`harness/tools/r2-url-probe/`（24 变体 × Go 语义基准，直调生产 `validate_proxy_url`）。

```sh
cd harness/tools/r2-url-probe && cargo run --release
# [DRIFT] go=rej   rust=pass   "socks5://1.2.3.4:1080/ "
# [DRIFT] go=rej   rust=pass   "socks5://1.2.3.4:1080/\t"
# [DRIFT] go=rej   rust=pass   "socks5://1.2.3.4:1080/\r"
# [DRIFT] go=rej   rust=pass   "http://1.2.3.4:1080\\"
# --- 4 drift(s) vs Go semantics ---
```

- **期望**: Go `url.Parse` 不 trim——`"...:1080/ "` 的 `Path == "/ "`、`"...:1080\"` 的 `Path == "\\"`，均 `!= ""` → 拒绝（"proxy URL must not contain a path"）。
- **实际**: night-03 的启发式 `(u.path() == "/" && s.ends_with('/'))` 用**原始输入**判断显式斜杠，而 WHATWG 解析器先 strip 前后 C0 control 与 space：
  1. `"socks5://1.2.3.4:1080/ "` → 解析后 path=`"/"`（空格被剥）→ 第一个分支不命中（path=="/"），启发式看原始串以空格结尾 `ends_with('/')==false` → **放行**；
  2. 同理 tab/CR 变体；
  3. `"http://1.2.3.4:1080\"` → special scheme 把 `\` 规范化为 `/` → path=`"/"`，原始串以 `\` 结尾 → **放行**。

其余 20 变体全部 match（含 `//`、`/./`、`/;`、`/%2F`、大小写 scheme、空 `#`、`?query`、双斜杠、IPv6 括号等）——启发式主路径正确，仅边角错位。

## 根因猜测

`crates/creance-net/src/egress.rs`（validate_proxy_url 的尾斜杠分支）。修复本质是想在 WHATWG 表示里恢复 Go 的"显式 `/`"信息，但用了会被解析器前置 trim 破坏的原始串判定。修法：对 `s` 先做与 WHATWG 相同的 trim（`s.trim_end_matches(|c: char| c <= ' ')`）再做 `ends_with('/')`，或对 special scheme 直接比较 `s.trim_end() != u.as_str()`（规范化改变了形态即有路径/空白）。

## 未验证想法

- `\t`/`\r` 在 Go `url.Parse` 里是否同样保留于 Path（Go 只对 control 做有限处理）——Go 侧精确行为未实跑（本机无 go 工具链）；矩阵里标 go=rej 基于路径非空推断，置信度高。
- 该检查只影响配置卫生（拨号只用 host:port）——若未来 proxy_url 被用于构造 HTTP 请求路径则升级危害（当前代码路径不存在）。

## 建议修复方向（供第二天的人参考，非结论）

`let raw = s.trim_end_matches(|c: char| c.is_ascii() && c <= ' ');` 后以 `raw.ends_with('/')` 作为显式斜杠判定；`\` 变体对 special scheme 在 parse 前把 `\` 归一为 `/` 再判断，或接受此 1 变体漂移（危害不至 S5 以上）。
