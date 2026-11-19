# STATE — 2026-11-19T10:05:00Z（R4 修复面回归+常规收尾会话 · 终稿）

## 已覆盖（attack-surfaces 条目 + 一句话结论）

- **night-05 修复面全量回归（R4 首要任务）**：
  - **F-020 sudoers 摘除**：全新 VM（/tmp/r4-f020，浅路径）实机电池——sudo -n 拒、无 pkexec、唯一 shell 用户=生成身份+root、setuid 全标准面、/etc 唯一"可写"是 gpt-auto-generator 的 /dev/null 掩码 symlink（假警报）、guestagent 无 unix socket、/dev/fuse world-accessible（仅 fuse 挂载无提权路径）、**stop→up 重放后 sudoers 摘除存活**（boot_id 已换）。结论：**修复无洞**。残留=provision `set -e` 若 apt 失败则 iptables+sudoers 摘除都不做（fail-open 窗口，依赖 lima 对 provision 失败的处理，未实证）。
  - **F-026 reap 特征**：regex 对自家 spawn 全命中（argv 固定序），实例名 alnum+dash 无 metachar 注入；`HostKeyAlias`+`-R` 双段唯乱性成立。真洞在**时序**：ensure/reap 竞态窗口 + Closed 守护的 `tunnel::stop` 每拍删共享 pid 文件（→F-028 的战争机制）。
  - **F-021 pidfile**：**FINDING-027**（S4，双验证）——僵尸 ssh 骗过 kill(pid,0)+start token，ensure 永久短路，gate Open+死 wire；legacy 裸 pid 回退窗口=同 uid 自伤面维持原判。
  - **F-022③ 48-hex 扫描**：token()=hex::encode 恒小写 → 大写/49+ 形状无实际意义；边界语义分歧（host 扫描 exact-48 双边界 vs guest env 探针 `grep -E '[0-9a-f]{48}'` 无边界，≥48 长哈希即误报 ESCAPE）=探针质量 S5（F-011 家族新面，未单列）；编码包装（base64 等）逃逸扫描=探针哲学局限。
  - **F-019 活性校验**：**FINDING-028**（S2）+ **FINDING-029**（S4），见下。
  - **C3 gate 并发黑盒**：hammer 12 轮（7 轮自然双守护）+ 确定性双守护三布局 + 冻结守护触发 retire 误删。单守护不变量全部正确：closed⇒隧道排空、forged renew/grant 拒绝且关窗、record/config 原子写、双 up 竞态是唯一入口。
- **B1/B2（SOCKS5/HTTP CONNECT 恶意服务器）**：实测 15 变体（b1-socks5-probe）——全部 fail-closed ✓；**FINDING-030**（S5）dial 目标 CRLF 注入 CONNECT 头（生产不可达，API 硬化）；auth 应答版本字节不查（Go x/net 平价未定证，无安全影响）；204 拒绝与 Go 逐字对齐。
- **B5/B6（DoH 应答/deadline）**：源码审查结案——429/5xx 三次有界重试、id/response 校验、question 段不比对（投毒者须先控代理=无新获权，设计注记）；deadline 在 socket 上贯穿全握手（工具变体 K/J 实证）。
- **C5（sync_proxy_revision）**：采纳矩阵与 Go 对齐；`!revision_changed && !binding_completed` 分支对 exit_policy 变更静默忽略（0.4 无输入面，**0.5 落地时必须重审**）。
- **F3（core.sock）**：审查结案——假 sock=同 uid 自伤面，无 fail-open。
- **record/config 写入原子性**：均 tmp+rename/write_private_atomic——corrupt-record 与半截 config 读竞态排除。
- **E1/E2 欠账核对**：INDEX 无欠账（F-011 即 night-03 已记录）。

## 进行中（无——本轮收敛干净）

## 下一步（按序 3 条）

1. **F-027/028/029 修复后回归**：run_daemon 身份绑定（record socket/run_id 比对）、spawn 互斥、retire 判定按 errno 分级、entry_alive 僵尸排除（p_stat==SZOMB 或 waitpid WNOHANG）、ensure 收割 ssh 子进程。修复顺序建议 028→029→027（028 是 029 的放大器，027 被 028 的战争持续喂养）。030 顺手：split_addr 拒 C0 控制字符。
2. **未验证想法池**：provision apt 失败 fail-open 窗口（强制断网 first boot 实证）；真 backlog ECONNREFUSED 变体（filler 已修 fcntl）；ensure/reap 竞态窗口确定性复现；C5 静默忽略分支在 0.5 的暴露面。
3. 攻击面地图剩余未覆盖项已极少：E3（workbench CSRF——F2 审查已扫过大半）、C7（fingerprint 稳定性）、C2 补深、G4 收尾。B/C/F 全线已覆盖；下一大项是 0.5 exit-policy 证据链（用户既定方向，reviewer 可在该分支落地后重开 E1/C5/探针面）。

## 关键记忆（≤10 条）

1. **`run_daemon` 退出条件只有"record 路径存在"**——任何后继守护的 record 都让 rogue 永生；rogue 的 gate 经 record 不可达（无 token），只能靠 `creance stop` 清场。
2. **retire_stale_record 是 `!is_ok()` 全杀**（5s 读超时=守护死了），而 close_gates 只认错误串含 "unreachable"——同一文件两套判定，前者激进后者保守。
3. **僵尸骗过双重活性验证**：kill(pid,0) 对僵尸返回 0 + kinfo_proc 保留 starttime——pidfile 的 pid+token 双验证对僵尸双双失效；生产代码对 ssh 子进程零 wait。
4. **`limactl list --json` 对 Stopped 实例仍报 sshLocalPort**——ensure 对停机实例照常 spawn ssh（秒退）；有 Closed 守护在删 pid 文件时演变成 500ms 无限 spawn 循环。
5. **gate-open CLI 不能复活守护**（record 没了只会报错）——只有 up→spawn_daemon 会重生；hammer 测试设计必须每轮 up。
6. **pgrep 自匹配陷阱**：探测 shell 的命令行含未加括号的 `gate-daemon <profile>` 字面量时，kill 循环会杀掉自己的 shell（教训：模式加 `[-]` 或精确匹配 exe 路径）。
7. macOS 无 `timeout`（GNU coreutils）；rustc 独立编译用 `unsafe extern` 声明 kill/sysctl 即可；macOS socket() 无 SOCK_NONBLOCK，需 fcntl O_NONBLOCK。
8. guest /etc/systemd/system-generators 下的 gpt-auto-generator 是 Ubuntu 的 /dev/null 掩码 symlink——`find -writable` 跟链产生假警报。
9. 双 `creance up` 并发在 hammer 中 7/12 轮自然产生 daemons=2——spawn_daemon 去重在竞态下完全失效，不需要刻意构造。
10. tools 的 cargo 工具先例：独立 crate + path dep + 空 `[workspace]` 表 + `CARGO_TARGET_DIR=/tmp`（如 b1-socks5-probe/a7-response-probe）。

## 会话统计

- 本会话发现：**4 个新 findings（027 S4 / 028 S2 / 029 S4 / 030 S5）**；027/028/029 全部实机复现（027 双验证），030 实测注入成立+生产不可达论证
- F-020 回归：**无洞**；F-022/F-026/F-021 源码面：时序洞并入 027/028
- B1/B2/B5/B6/C5/F3 常规项全部结案（攻击面地图 A–F 除 E3/C7 外全绿）
- 环境已清理：VM stop+delete+rm、/tmp 工件清除、427 个悬空 cage-lima-* 链接清除、残留进程 0
- 累计：**30 findings**（027/028/029/030 待修复）
- 工具留档：harness/tools/ 新增 zombie-pidfile、c3-gate-hammer、f019-backlog、b1-socks5-probe 四个工具
