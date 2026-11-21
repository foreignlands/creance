# FINDING-056: reap_orphan_cores 把 profile 目录路径未转义拼进 pgrep ERE——元字符目录漏杀自己、误杀别目录

- **编号**: 056
- **严重度**: S4（漏杀→start 楔死自伤；过匹配→同 uid 跨目录杀进程）
- **攻击面**: H6（service.rs 孤儿收割，2026-11-21 新代码）
- **发现时间**: 2026-11-21T12:10:00Z
- **发现者会话**: r13（night-auditor-v2）
- **状态**: 待修复

## 复现（必须）

工具：`harness/tools/r13-orphan-probe/`（README/fakecore.c/probe.sh）。假核心 =
pause 二进制，argv 形状与真 mihomo 一致（`{d}/mihomo -d {d} -f {d}/config.yaml`），
双 fork 脱离父进程达 ppid==1。对**真** `target/release/creance proxy-stop` 实测：

```sh
cd harness/tools/r13-orphan-probe
# A 正控（无元字符）：收割网正常 → 证明探针鉴别力
bash probe.sh setupA   # PID=69373 PPID=1
CREANCE_CONFIG=/tmp/r13-ere/plain/config.json ../../target/release/creance proxy-stop  # RC=0
# → 假核心被 TERM，死亡 ✓

# B 漏匹配（目录含 +）：
bash probe.sh setupB   # PID=69440 PPID=1
CREANCE_CONFIG=/tmp/r13-ere/a+b/config.json ../../target/release/creance proxy-stop   # RC=0
ps -o pid,ppid,command -p 69440   # → 假核心仍存活 ✗（自己孤儿没被收割，且 stop 谎报 RC=0）

# C 过匹配（a+b 的 ERE 命中 aab 的核心——跨目录误杀）：
bash probe.sh setupC   # aab 内孤儿 PID=69477 PPID=1
CREANCE_CONFIG=/tmp/r13-ere/a+b/config.json ../../target/release/creance proxy-stop
# → aab 的孤儿被 a+b 的 stop 杀死 ✗（别的 profile 的核心被误杀）

# D 畸形（目录含未闭合 "("）：pgrep regcomp 失败
bash probe.sh setupD; CREANCE_CONFIG='/tmp/r13-ere/paren(1/config.json' ../../target/release/creance proxy-stop
# pgrep: Cannot compile regular expression … (parentheses not balanced)，RC=2
# → creance 静默吞掉（output() 只取 stdout），stop RC=0，假核心存活 ✗
```

另附 ERE 语义独立证据：`sleep 30 & pgrep -f "slee+p"` 命中该 sleep（量化符活跃）。

- **期望**: 收割网对任意合法目录名精确匹配本 profile 的孤儿；regcomp 失败应至少
  噪声化（stop 输出警告），不该 RC=0 谎报干净。
- **实际**: 四场景如上——`+` 漏杀（下次 start 必楔死在"端口已被占用，请更换独立
  端口"，文案还指向用户端口选择而非本缺陷）、`a+b`↔`aab` 跨目录误杀、`(` 静默失效。

## 根因猜测

`crates/creance-proxy/src/service.rs:210-211`：`format!("{d}/mihomo -d {d}")` 直接作为
`pgrep -f` 的 ERE。profile 目录 = 用户 config.json 所在目录（`store.rs dir()` →
`paths::join(profile,"proxy")`），用户可自由含 ERE 元字符。对照组：tunnel.rs:75 的
签名用的是 vmname 折叠后的安全字母表 instance 名（D1 纪律）——同一仓库里收割网
已有"输入先进安全字母表"的正确先例，service.rs 侧没有执行。

## 未验证想法

1. **裸 pid TOCTOU**：pgrep→ps→kill 之间 pid 退出并被复用 → TERM/KILL 打到无辜
   新进程；2s 等待窗（service.rs:244-257）用 kill(pid,0) 判活，pid 复用会把窗口
   拖满并对复用者 SIGKILL。违反项目自身纪律（F-021/F-027 start-token 核验）——
   但确定性复现需 pid 空间回绕探针（macOS pid 上限 99998，量级 ~10 万 fork），
   本轮未做。
2. `.` `[` `\` 等其余元字符的漏杀/误杀变体未逐一实测（`(` 已实测，`+` 两方向已实测）。
3. 跨 uid：pgrep 默认匹配所有用户；他用户孤儿命中时 kill 得 EPERM，process_alive
   的 EPERM=alive 分支会白等 2s 再空 KILL——无越权杀，只有延迟+谎报成功。

## 建议修复方向（供第二天的人参考，非结论）

签名只用 hash 后缀（profile 的 SHA256 前 4 hex 已是安全字母表，socket() 已这么
做），如 `mihomo -d {d} 0x{hash4}` 并在生成 core config/argv 时带上该标记；或
`pgrep -f` 换成 `preg_quote` 式转义；regcomp 失败（pgrep RC≥2）显式报错。
