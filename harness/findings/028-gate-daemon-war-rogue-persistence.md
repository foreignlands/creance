# FINDING-028: 双守护战争——败者凭"record 路径存在"永生，closed 态 rogue 每 500ms 杀隧道，wire 颤动且不可管理

- **编号**: 028
- **严重度**: S2（closed≠wire down 契约破坏；前提是守护双抛竞态，触发后状态**永不自愈**）
- **攻击面**: night-05 修复面回归（F-019 活性校验的守护生命周期设计），attack-surfaces C3
- **发现时间**: 2026-11-19T08:30Z
- **发现者会话**: R4 (s01)
- **状态**: 待修复

## 复现（必须）

工具：`harness/tools/c3-gate-hammer/`（hammer.sh）+ 直接 `creance gate-daemon`
子命令（绕过 spawn_daemon 的去重，确定性构造；`creance up`×2 并发在 12 轮
hammer 中 7 轮自然产生 daemons=2）。

```sh
# 0) VM 运行 + 单守护
creance up && creance gate-open
# 1) 直接再抛一个守护（run_daemon 本身无去重，去重只在 spawn_daemon）
creance gate-daemon <profile> <instance> <config> <instance_dir> <port> &
sleep 1.5
creance gate-open        # 打开 record 属主的 gate
# 2) 观测
# host: pgrep -f 'HostKeyAlias=lima-<inst>' 每 0.5s 采样 → 隧道 pid 每拍更换
# guest: 对 127.0.0.1:<port> 每 0.25s 探测
creance shell bash -lc 'for i in $(seq 1 24); do timeout 1 bash -c "</dev/tcp/127.0.0.1/17896" && echo -n UP || echo -n ··; sleep 0.25; done'
```

- **期望**: 单实例至多一个守护；closed ⇒ wire down；gate 控制面可达全部守护。
- **实际**（15:26-15:31 实测三轮布局）:
  - 双守护共存（ps 双 pid，ppid=1）。
  - **record=open + wire 颤动**：guest 视图 `······UP······UP······UP······UPUP····UPUP····UP`（~500ms 周期 UP/死交替），host 隧道 pid 每拍更换（13030→13036→…→13067，~600ms 一只）。
  - **record=closed + wire 间歇 up**（第三个守护的 rename 覆盖 record）：guest 视图 `················UP······UP······UP······UP`——**canonical record 报 closed 期间 wire 周期性可用**。核心运行时，guest 内重试循环即可在"closed" gate 下获得出网（本测核心未起，机制链完整：ssh -R 接受→转发宿主核心）。
  - rogue（Closed 态败者）**永不退场**：run_daemon 只判 `record 路径存在`（gate.rs:776），任何后继守护的 record 都让它永生；其 gate 状态/token 经 record 不可达（record 被 rename 覆盖），**无法被 gate-close/close_gates 管理**。多轮实验中 rogue 累计 3+ 只，全部活到 `creance stop`。
  - 1.5s 采样：某 rogue 在 record 删除+CONT 后 ≥1.5s 仍在（后续证实因新 record 立即被后继者写入而永续存活）。

## 根因猜测

- `crates/creance-gate/src/gate.rs:759-785`（run_daemon 主循环）：退出条件
  只有"record 文件不存在"，没有"这份 record 是我的"绑定（比对 socket/token
  或 run_id）——败者把后继者的 record 当自己的续命符。
- `crates/creance-gate/src/gate.rs:224-251`（Gate::start）：socket 目录随机
  （`cage-gate-<token8>`）+ record 原子 rename 覆盖——双抛无互斥，败者
  不自毁。spawn_daemon 的去重（gate.rs:690-702）在两进程同时通过检查时
  双双失效。
- watchdog 的 state 分支（gate.rs:299-314）：Open→ensure / Closed→stop+reap
  共享同一 `proxy/tunnel.pid` 文件，两个守护的 stop/ensure 乒乓把 pid 文件
  当共享缓冲区反复删除/重写 → 隧道 500ms 颤动（另见 F-027：战损 ssh 全是
  僵尸）。
- `tunnel.rs:105-125`（reap）： Closed rogue 每 500ms 全 signature 扫杀
  （只豁免当时 pid 文件属主）——war 的杀伤端。

## 未验证想法

1. 端到端出网验证（需核心运行）：war + guest 重试循环在 record=closed 下
   的实际吞吐——机制链已闭合（UP 相位 ssh -R 接受连接→转发宿主端口），唯
   未起核心实测字节。
2. rogue 的 socket 目录（/var/folders/.../cage-gate-<token8>/）在 rogue
   永生期间持续存在——200+ 并发连接 dump（F-019 实验已对 record 属主做过
   200 连接）对 rogue 同样可行，线程数无上限（gate accept 每连接 spawn，
   gate.rs:340-343，无 serve.rs 的 64 上限）。
3. `creance stop` 的 close_and_remove 只给 record 属主发 close——rogue 只靠
   record 消失退场；若 stop 与 rogue 的 500ms tick 竞态（record 删除前
   rogue 恰好 stop+reap），是否产生 stop 后残留隧道（reap 兜底应扫掉）。

## 建议修复方向（供第二天的人参考，非结论）

1. run_daemon 绑定身份：循环里同时校验 record 的 socket==自己绑的路径
   （或 run_id），不匹配即退场（renamed-over = 我已不是 canonical）。
2. Gate::start 前置互斥：record 写入前用 O_EXCL 锁文件/pidfile CAS 声明
   所有权，败者在 rename 失败/record 已有更近 run_id 时自毁。
3. watchdog 的 ensure/stop 决策读取 record 归属（只有 canonical 才执行
   stop/ensure），rogue 状态一律 no-op。
4. spawn_daemon 抛守护后确认"存活且是 record 属主"，否则杀掉刚抛的 pid。
