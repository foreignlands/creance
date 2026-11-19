# STATE — 2026-11-19T07:20:00Z（R3 第三轮审查 s01 · 终稿）

## 已覆盖（R3 全部优先级完成，5 findings：019-023）

### P1 0.3/0.4 新面回归审查

- **guest 防火墙绕过 → F-020 (S2) 实测逃逸**：lima 默认 guest 用户（宿主同名 uid=501 镜像）持 passwordless sudo；guest 内 `sudo -n iptables -P OUTPUT ACCEPT && -F` 一条命令撤防，撤防前 curl 直连 BLOCKED、撤防后直连 https://1.1.1.1 得真实 301——gate/mihomo/审计全部绕过。escape-test 如实翻转（net-direct-egress/dns → ESCAPE）——探针有效，**强制层可被 guest root 一键撤销**。根因=generate_lima_yaml 无 user:/sudoers 定制。修法：lima `user: {name: <profile.username>, sudo: false}`（与 F-022①username 接线联动）。
- **gate-daemon → F-019 (S4) 实测全链**：SIGKILL daemon → record 残留（唯一删除点在 GateHandle::drop）→ 后续每次 `creance up` 被 spawn_daemon 的 record 去重短路（无 daemon/无 watchdog/Err-才-fallback 不触发）→ 孤儿 ssh -R 持续供网且 gate-close CLI socket 不可达 → **wire 无法关闭（违反 closed=wire down 契约，fail-open）**；escape gate 探针只查 record 文件存在 → Contained 假 PASS。cmd_stop 注释声称 "removes cage-gate.json → daemon retires" 实际无人删（run_daemon 只在 record 消失后 break——**循环依赖**，注释与实现不符）。修法：record 存在时先 socket 活性检查；close_gates 文件级 fallback；探针 record 存在+socket 死 → Escaped。
- **tunnel.rs → F-021 (S4) 实测误杀**：stop() 按 pid 文件盲杀——伪造 tunnel.pid 指向 victim sleep 进程 → `creance stop` SIGTERM 杀死 victim（实测）。running.rs 对同类问题有 kinfo_proc start-time 校验而 tunnel.rs/gate.rs 没有——0.3 新代码重现旧缺陷模式。修法：提公共 start-token 助手，pid 文件记 {pid, started}。
- **guestprofile → F-022 (S4)**：①username 死字段——生成/校验/持久化齐全但 provision 不创建用户，guest 实际身份=宿主用户名镜像（id 实测 uid=501(shenyiyu)；tunnel.rs User=$USER 同）——与 "generated identity" 声明冲突，宿主真实用户名进 guest；②load_or_create 读失败（权限损坏）与不存在不可区分 → 身份静默重置（违背自身 never-overwrites 注释）；③credentials-are-session-only 探针只 validate 单文件（声明扫描 profile 目录的 token 形状——store.auth/gate token 同形状秘密未扫，假 PASS）。
- **gate watchdog 阻塞**：ensure/stop 在 drop(inner) 后跑 ✓ 不拖主循环（只是轮询退化为 1s+）；check_id 并发窗口 fail-closed ✓（Mutex 串行）——无新 finding。
- **spawn_daemon pid 复用**：与 F-021 同修（gate.pid 同样无 start-time）。

### P2 上轮受限项

- B5 DoH（rustls webpki 硬编码）/C3 gate 并发（gate 未接线，0.4 后 gate-daemon 已接线！**下轮可用 gate-daemon 运行实例做并发黑盒**）/E3（R2 已闭环）——B5 仍受限记档；C3 状态更新为"已有运行实例可测（本轮 gate-daemon 实测即是部分 C3）"。

### P3 新攻击面快扫

- root 跑 install.sh：R2 引号审查仍适用；root+本地 .toolchain 投毒=同 uid 已控面，无新面。
- lima.yaml workspace 注入：R2 已审（结构化 serde_yaml）✓。
- tunnel ssh 参数注入：instance 名 vmname 折叠 ✓；USER env 未校验已并入 F-022①（修 username 接线时一起消）。
- **深路径 setup → F-023 (S5) 实测**：macOS /var/folders 深路径 profile 撞 UNIX_PATH_MAX，limactl fatal 原样抛出（预算 clamp 下限仍不够）；浅路径 /tmp/p1 正常。creance 侧需预检+可行动报错。

## 进行中

无。R3 任务单全部完成。

## 下一步（按序 3 条）

1. **night-05 修复会话**：019/020/021/022/023 五项（修法建议在各自文件）。**020 最高优先**（S2 逃逸）——lima user 块 + sudo:false + username 接线是一个原子修复。
2. 修复后 **R4 验证**：新 guest 用户态下重跑 sudo 撤防测试（应失败）+ daemon SIGKILL 恢复路径 + escape 全绿；C3 正式并发黑盒（gate-daemon 现有运行实例）。
3. **F-020 关联**：RELEASES/README 的 containment 声明应注明边界（"guest 内非特权进程" vs root）直到修复落地。

## 关键记忆（≤10 条）

1. **R3 全部 5 findings 都有实测/可复现探针**——VM 全链实测（/tmp/p1 实例）是本轮核心方法：sudo 撤防、daemon kill、pid 盲杀均一次跑通。
2. 020 的本质：**provision 用 root 设防，但 guest 日常用户是准 root**（lima 默认 sudoers）——强制面强度=最弱特权路径。0.4 的 guestprofile.username 本来就是解药，差最后一步接线。
3. 019 的模式：**文件存在≠进程存活**——record/pid 文件都是"曾经活着"的证据；spawn/探针一律需要活性验证（socket ping / start-time token）。
4. 循环依赖：run_daemon 等 record 消失、record 只被自己的 Drop 删——daemon 实际服务到进程死亡；cmd_stop 注释与实现不符（作者以为 close_gates 删文件）。
5. macOS /var/folders 深路径（~92 字符 canonicalize）+ lima socket 27 字符 → UNIX_PATH_MAX 104 必超——临时目录做 profile 在 macOS 上不可用（F-023）；浅路径 /tmp/p1 可用。
6. escape-test 探针体系两处假 PASS（credentials-are-session-only 单文件 validate；gate-record-private 文件存在性）——探针质量=F-011/016 同族问题的 0.4 新增面。
7. VM 实测耗时参考：镜像缓存命中时 setup+up ≈3 分钟；apt provision 在防火墙设置前 ✓（provision 脚本顺序正确）。
8. tunnel.rs `ControlMaster=no/ControlPath=none/StrictHostKeyChecking=yes/ExitOnForwardFailure=yes` 全部正确 ✓；-R 绑 loopback ✓。
9. guest 的 apt/DNS：provision 在 iptables 前完成出网操作 ✓；运行期 guest 无 DNS（nameserver 流量被 DROP）——远程解析走 mihomo socks5 ✓ 设计自洽。
10. pgrep -f "gate-daemon" 会匹配审查者自己的 shell（命令行含该词）——判活用 pgrep -lf 看全命令行。

## 会话统计

- R3-s01 发现数：5（019 S4、020 S2、021 S4、022 S4、023 S5）
- 累计：23 findings（R1 14 + R2 4 + R3 5）
- 实测证据：019/020/021/023 全部 VM/进程级复现；020 为 S2 级实测逃逸
- 工具/环境：/tmp/p1 临时 profile 已 stop 并删除；无宿主残留（唯一遗留=lima 镜像缓存，无害）
- CI 基线：R3 开工时全绿；仓库只读保持
- **建议**：020 需要设计决策（sudo 移除 vs 锁 iptables）——修复会话前建议用户确认 workload 是否依赖 guest root。
