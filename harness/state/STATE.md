# STATE — 2026-11-19T09:05:00Z（night-06 修复会话 · 终稿）

## 已完成（R4 全部 4 findings + 修复中再挖 2 个 = 6 项，全部实机验证；累计 31 findings 全闭环）

- **F-028（S2 双守护战争）✅ 4b79cc1 + a274a3b（disown 补丁）+ 实机复验**：run_daemon 绑定 record 身份（run_id 比对）——败者 ≤1 tick 退场且 disown（drop 不删胜者 record、不碰 wire）；watchdog 每 tick still_owner 检查（非属主不动 wire）。**实机重演双抛：daemons=1、隧道 pid 稳定、guest wire `UPUPUPUPUPUPUPUP`（R4 颤动消除）、record=closed 期间 wire 稳定 down（fail-closed）**。第一版修复漏了 GateHandle::drop 的无条件删 record——实机重演抓到"败者退场删胜者 record→胜者误判退役→全灭"级联，disown 语义补上（回归测试覆盖）。
- **F-029（活性判定）✅ 4f7a10f + 实机复验**：daemon_serving（connect 层证据：connect 成功=活（含冻结形态），仅 ECONNREFUSED/ENOENT=死，其余保守当活）；retire_stale_record 与 close_gates 统一用它（"unreachable" 字符串判定废除）。**实机：SIGSTOP 冻结守护后 `up` 纯 no-op（record 在/守护未换/隧道未动）**。UnixStream::connect_timeout 不存在（那是 TcpStream 的）——unix 用 connect_addr（本地 connect 即时完成，R4 filler 200 连接实证不阻塞）。
- **F-027（僵尸）✅ c8ae970 + 实机复验**：entry_alive 开头 waitpid(pid,WNOHANG)——调用者自己的已退出子进程当场收割+判死（非子进程 ECHILD 不受影响）；ensure settle 窗口后验证（秒退不当 established）；reap_orphans 每次杀前重读 owned（pgrep 快照后的 ensure 认领不再被误杀）。**实机：kill -9 隧道 → t+1s 重生（34773→34910）+ guest wire UP（R4 实测修复前 +4.5s 无重生）**。
- **F-030（dial CRLF）✅ 618e48f**：split_addr 拒绝 C0 控制/DEL/空格（R4 M2 的注入形状全数入回归）。
- **F-031（provision fail-open）✅ cfd5733**：R4 在 F-020 回归留的未验证想法，核实成立——set -e 下 apt/curl 失败=防火墙+特权摘除全不执行（guest 裸奔态）。安装步骤全部 || true，锁定+摘除必达（脚本注释写明契约顺序）。
- **附带修复（实机暴露的误报）**：credentials 探针的期望集漏了 store.revision（48-hex 版本号，proxy-select 写入 config.json/sources.json）——真实 import+select 流程触发 ESCAPE 误报，单测没覆盖该流程；期望集补齐+测试补 store.revision 路径。

## 实机验证总结（/tmp/creance-n6 全新实例，direct 节点 + managed core）

- 双守护收敛（1 只、无颤动、fail-closed 正确）✅；冻结 no-op ✅；僵尸 1s 重生 ✅
- escape-test 全绿（含 proxy-path PASS）+ 真实出网 trace（经隧道→core→direct，出口 ip=142.249.39.221）✅
- 首次 proxy-start 偶发未起（第二次成功，core running: true）——launchd 首次注册时序，低优先记档未立 finding
- guest 探测注意：`/dev/tcp` 是 bash 特性，`limactl shell sh -c` 下必误报全 down——要用 `bash -c`（本会话自伤一次）

## 版本

v0.4.2（tag）：night-06 hardening。31/31 findings 闭环。

## 下一步（按序 3 条）

1. **R5 回归审查**（重点：night-06 修复面——run_id 绑定的边角（record 留 Old 值的瞬间）、disown 与 stop 并发、waitpid 判定的调用者相关性、daemon_serving 的 connect_addr 语义、provision || true 后的工具链半装态；E3/C7 未覆盖项）
2. **0.5 exit-policy 证据链**（gate-open grant 从自检升级为出口 IP 实测证据——trace→大陆网段+锚定比对）
3. 模型驱动逃逸演练 + Devin 云端介入（文档就绪，时机由用户定）

## 关键记忆（≤10 条）

1. **GateHandle::drop 的无条件副作用是多进程所有权场景的地雷**——drop 语义必须与"我是否仍是属主"绑定（disown 模式）。
2. **UnixStream 没有 connect_timeout**（TcpStream 才有）；本地 unix connect 即时完成/拒绝，connect_addr 即探针。测试"冻结守护"用 bind-不-accept 的 listener 形态（不是普通文件——非 socket 的 connect errno 不同）。
3. 僵尸的判定只能靠 waitpid（kill(0) 与 start token 都骗过）；调用者相关性是特性不是缺陷：守护视角收割自己的僵尸子进程。
4. 实机重演是修复的验收标准——F-028 第一版修复被自己的实机重演打回（disown 级联），单测没抓住。
5. `limactl shell sh -c` 里用 `/dev/tcp` 必误报（dash 无此特性）——guest 连通性探测一律 `bash -c`。
6. 探针期望集必须跟产品写入的全部 48-hex 形状走（revision 也是 48-hex 版本号）——单测要覆盖真实 CLI 流程（import+select），不是手工拼 store。
7. R4 的三件套（僵尸/双抛/瞬时超时）都在"单文件单守护的静默世界"之外——并发与异常进程态是修复面的必查项。

## 会话统计

- night-06 修复：6/6（027/028/029/030/031+revision 误报），6 commit（4b79cc1→cfd5733+a274a3b），每 commit CI 全绿
- 累计 31 findings（R1 14 + R2 4 + R3 5 + R4 4 + night 自发现 4），全修复
- 环境：/tmp/creance-n6 已 stop+delete+清理；daemons=0 tunnels=0
