# STATE — 2026-11-19T11:00:00Z（R5 对抗性回归审查 · 会话记录）

## 会话定位

R5 = night-06（v0.4.2）修复面回归 + 收尾未覆盖项。基线 HEAD **96b72a2**（注意：0.5 gate-open
exit-evidence 已落地，gate.rs 的 open() 签名已变——grants 现在携带 evidence 模块的观察结果）。
基线验证：完整 `sh scripts/ci.sh` @96b72a2 全绿（CI_EXIT=0，14/14 suites，fmt+clippy+test+release）。

## 已完成（4 新 findings 032–035，全部待修复；累计 35）

- **F-032（S4）订阅 48-hex 伪造 escape-test 误报**：恰 48 个小写 hex、边界非 hex 的攻击者可控字符串
  （订阅 password 等任意字段）经 sources.json 被 scan_unknown_tokens 判 unknown → credentials 探针
  Escaped、exit 1。宿主侧实测复现 + 双对照（干净订阅绿；64-hex 常见形状不触发）。根因：扫描域含远程
  内容落点（escape.rs:239-301）。修复方向：扫描域剔除远程内容文件/内容级白名单。
- **F-033（S5）fingerprint-consistent 探针死代码**：fingerprint.txt 全仓库无写入者 → 恒 NotEnforced
  （"layer not implemented yet"）。漂移检测实际由 running.rs 承担。C7 同时闭环：指纹=结构体序列化
  sha256（字节序无关、exit_policy 先归一）；proxy_revision 有意入指纹（保守方向）。
- **F-034（S4）provision curl 残尸遮蔽 apt 兜底**：`curl -o` 中途失败残留半截 /usr/local/bin/node，
  PATH 先序遮蔽 apt 兜底装出的 /usr/bin/node → 兜底链被第一腿尸体击败。机制两前提各自实证（curl 留
  半截文件为文档化行为 + Ubuntu PATH 先序），端到端弱网链未实测。F-031 契约本身（锁定/摘除必达）核验成立。
- **F-035（S4）spawn_daemon 去重命中垂死守护**：确定性探针（harness/tools/r5-race-probe，判定逻辑逐字
  复制、被测守护为真实 release 子进程）：rm record → 立刻 spawn_daemon → Ok(()) 而终态无守护无 record
  （pidfile-alive 只证明进程存在不证明继续服务）。对照 r2/r3 全绿；r4 证明 F-028 disown 机制在损坏
  record 重生面成立（老守护安静退场、继任 record 完好）。对称风险：stop 的 close_and_remove 可刺杀并发
  up 的年轻 record（未实测）。修复方向：dedup 命中且 record 缺席时等待/复核，或 spawn 后确认。

## 回归核验（无发现，记档）

- run_id 绑定边角：rename 原子无撕裂读；持续损坏 record → 守护永生 + control 全 403 砖化 +
  watchdog 持线不动（gate Open 时=wire fail-open 直到外部 CLI，同 uid 自伤面；`rm`/CLI touch 即愈，
  宿主侧实测）。
- disown×stop/close_and_remove 并发：收敛 ✓；still_owner 在 record 消失拍 → 不动 wire ✓。
- waitpid 调用者相关性=特性（守护收割自家僵尸；CLI 视角 ECHILD 落 kill(0)）；settle 窗口慢启动误杀
  **证伪**——ensure 只对"已退出"的 ssh 报 Err，慢启动存活不误杀。
- daemon_serving 非 socket 路径：macOS 实测 regular-file/directory → ENOTSOCK → 保守当活（不 mutiny，
  方向正确）；dead listener → ECONNREFUSED → retire ✓。自伤面：record.socket 被同 uid 换成活文件/目录
  → record 永不 retire（记档）。
- E3（serve.rs workbench）：已覆盖无新发现——CSRF=POST 非空 Origin 必须精确等 `http://127.0.0.1:{绑实端口}`；
  GET 仅读；DNS rebinding Origin=攻击者域→403；import 任意 url 继承 B4 全套守卫。
- E1 过期状态修正：已并入 F-011（night-03 修复）；sock-abstract 现报 SKIP、mounts 计数为真 YAML 解析。

## 下一步（按序 3 条）

1. **0.5 exit-policy 证据链审查**（STATE 上轮第 2 条顺延）：evidence.rs observe/parse_trace/grant_checks
   已初读（fail-closed 方向正确：trace 失败=Err 不 grant；v6/缺 loc 拒绝）；待深挖：
   gate.rs `!revision_changed && !binding_completed` 对 exit_policy 变更静默忽略分支（C5 留的 0.5 复审项）、
   grant_checks 五个结构性 check 全部硬编码 "passed" 是否有真实核验、evidence 观测与 check 窗口的 TOCTOU。
2. F-032/033/034/035 修复（032/035 有实测探针可作回归）。
3. 模型驱动逃逸演练 + Devin 云端介入（文档就绪，时机由用户定）。

## 关键记忆（≤10 条）

1. **workspace crate 无法从仓库外链接**（zombie-pidfile 教训，R5 重新踩坑确认：workspace 继承的 path dep
   在外部 consumer 侧解析失败）——探针一律独立 rustc + 逐字复制判定逻辑 + 真实 release 子进程当被测物。
2. pidfile-alive 只证明"进程存在"，不证明"继续服务"——dedup 分支需要二次确认（F-035 根因）。
3. `curl -o` 失败留半截文件是文档化行为，`--remove-on-error`（≥7.71）是补丁位——任何"下载或兜底"链都要防残尸遮蔽。
4. 探针期望集只列"自己生成的形状"不够：扫描域内若有远程内容落点（sources.json），攻击者可伪造任何期望形状（F-032）。
5. macOS connect 非 socket 路径 → ENOTSOCK(38)；dead listener → ECONNREFUSED(61)——daemon_serving 的
   两分支边界实测。
6. escape-test 宿主侧探针不依赖 VM（guest-profile.json 存在即评）——预言机类探针可宿主侧快速回归。
7. `creance gate-daemon <profile> <inst> <config> <inst_dir> <port>` 可在无 VM 的宿主侧直接起真守护
   （Closed 态 watchdog 只做 stop+reap，不触 limactl）——守护面黑盒测试的最短路径。

## 会话统计

- R5：4 findings（032-035，全待修复）+ 5 个回归面核验记档 + E1/E2/E3/C7 四个攻击面状态更新
- 探针工件：harness/tools/r5-race-probe/（r1-r4 四轮，含 F-035 复现与 F-028 回归对照）
- 环境：/tmp/r5* 全清理；无残留守护进程（pgrep 复核 0）；仓库只读未被修改（findings/STATE/attack-surfaces/tools 除外）
