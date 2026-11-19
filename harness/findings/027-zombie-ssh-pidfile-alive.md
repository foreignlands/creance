# FINDING-027: 未收割的 ssh 僵尸被 pidfile 判活——ensure 永久短路，gate Open 但 wire 死

- **编号**: 027
- **严重度**: S4（fail-closed 方向：可用性/契约破坏，非逃逸）
- **攻击面**: night-05 修复面回归（F-021 pidfile × F-026 ensure/reap 的一致性），对应 attack-surfaces C3/C6 邻域
- **发现时间**: 2026-11-19T08:05Z
- **发现者会话**: R4 (s01)
- **状态**: 待修复

## 复现（必须）

机制级复现（无需 VM），工具：`harness/tools/zombie-pidfile/`（独立 rustc 二进制，
逐字复制 pidfile.rs 的 `signal_alive`/`process_start_token`/`entry_alive`）：

```sh
cd /Users/shenyiyu/Documents/zcode/claude-cage-rs/.toolchain  # 工具链 env
rustc -O main.rs -o /tmp/r4-zombie-probe --edition 2024 \
  harness/tools/zombie-pidfile/main.rs
/tmp/r4-zombie-probe; echo "exit=$?"
```

- **期望**: 已退出且未被 wait 的子进程（僵尸）不应被 pidfile 判活——
  `tunnel::ensure`（tunnel.rs:20-24 的 `pidfile::alive` 短路）应能识别
  "隧道进程已死"并重新 spawn。
- **实际**（PROBE_EXIT=42）:

  ```
  pid=6910 started_at_write="1795071768 300511"
  after exit: signal_alive=true token_now="1795071768 300511"
  pidfile::alive equivalent = true
  VULN CONFIRMED: a zombie child of the caller reads as alive
  ```

  僵尸对 `kill(pid,0)` 返回成功（信号可投递、被丢弃），且 sysctl
  KERN_PROC_PID 对僵尸仍返回原 start timeval → start token 匹配 →
  `entry_alive` 恒真。生产链前提成立：`grep -rn "\.wait()\|waitpid\|try_wait"
  crates/creance-{vm,gate}/src` 仅测试代码命中——**gate 守护（长活进程）
  经 watchdog 每 500ms 调 `tunnel::ensure`（gate.rs:308-313），spawn 的 ssh
  死后变僵尸且永无人收割**。

### 完整故障链

1. gate Open 期间 ssh 因任何原因退出（macOS 休眠唤醒断 TCP、auth 失效、
   ExitOnForwardFailure 触发——均现实高频）；
2. ssh 成 gate 守护的僵尸子进程；pidfile（pid+start token）继续判活；
3. watchdog 每 500ms 的 `ensure` 在 tunnel.rs:22 短路 → 永不 respawn；
4. **gate 持续 grant Open，guest 的 `127.0.0.1:<port>` 连接拒绝（wire 死），
   直到守护重启/close**。Open⇔wire-up 契约（gate.rs:294-298 注释自述）破坏。

## 根因猜测

- `crates/creance-vm/src/pidfile.rs:58-67`（`signal_alive`）：`kill(pid,0)==0`
  对僵尸为真——POSIX 语义本身如此，缺陷在于用"可信号"当"活着"。
- `crates/creance-vm/src/pidfile.rs:72-84`（`entry_alive`）：start token 对
  僵尸依然匹配（kinfo_proc 保留 starttime），双重验证对僵尸双双失效。
- `crates/creance-vm/src/tunnel.rs:82-84`：spawn 后只写 pidfile，从不
  `wait()`/`waitpid(WNOHANG)`——僵尸的制造端。
- `crates/creance-gate/src/gate.rs:280-315`：watchdog 是唯一"期待隧道活着"
  的循环，但它的活性判定全部依赖被僵尸欺骗的 pidfile。

## 未验证想法

0. **实机端到端已验证**（2026-11-19 15:36，单守护、gate open、实例运行）：
   `kill -9` 隧道 ssh（pid 20721）→ 1.5s 后 `ps stat=Z`（父=守护 20562），
   `tunnel.pid` 仍记 20721 且 token 匹配；再等 3s **无重生**（ensure 在
   僵尸上短路，死 wire 永续直到守护退出）。机制探针与实机链一致。
1. **ensure/reap 竞态窗口**（源码级确认，live 未复现——窗口为 spawn→write
   的 µs-ms 级）：`reap_orphans`（tunnel.rs:115-124）只读取**一次** owned pid
   （文件里那个），随后 kill 所有特征匹配项。并发 close/stop（另一进程的
   `close_and_remove`/`run_daemon` 退出路径）在 ensure 的 spawn 与 write 之间
   执行 pgrep→kill 时，会杀掉"pid 文件即将拥有"的新 ssh；ensure 仍然返回
   Ok。另注意 pgrep 在 kill 循环之前完成快照，即使 write 先于 pgrep，
   owned 仍取自旧文件内容。后果同上：Open + wire 死 + 死进程进 pidfile。
   ——F-028 的守护战争每 500ms 大量制造该窗口，实际触发频率远高于双终端
   手工并发。
2. 僵尸态下 `pidfile::stop`/`reap_orphans` 对僵尸 SIGTERM 全部空转——只有
   守护进程退出（init 收割）才能解除短路。重启 VM 不重启守护时（stop→up
   流程是否重启守护待 C3 验证），故障可能跨 VM 生命周期持续。
3. macOS `pgrep` 是否列出僵尸未验证（若是，reap 的快照里僵尸命中但 SIGTERM
   空转，反而掩盖死因）。
4. 双 `up` 并发（两个 CLI 进程同时过 `pidfile::alive` 检查）→ 双 ssh，
   第二个因远端转发占用退出（ExitOnForwardFailure）→ 立即制造一只僵尸 +
   pidfile 指向僵尸 → 同一故障链。这比休眠唤醒更容易自然触发。

## 建议修复方向（供第二天的人参考，非结论）

1. 修僵尸判定：`entry_alive` 增加僵尸排除——sysctl kinfo_proc 的
   `p_stat == SZOMB`（darwin `p_stat` 在 kp_proc.p_stat）或尝试
   `waitpid(pid, WNOHANG)`（非子进程返回 ECHILD=仍在，子进程可收割）。
2. 修制造端：ensure spawn 后用 `Child::try_wait` 周期收割，或改用
   spawn-daemon 式双进程（detach+立即 wait）避免守护留僵尸。
3. 修竞态窗口：reap 循环每次 kill 前重读 pidfile 的 owned；ensure 在
   write 后重验 `child.try_wait()`（秒退即报错），并用独有 token 段
   （如 `-o HostKeyAlias=...` 之外再带一个随机 tag）缩小误杀面。
