# FINDING-068: fs-flag-readable 旗标 oracle 从未被放置——产品默认流程里该探针恒 PASS（空探针），三处声明面却把它列为"已强制"

- **编号**: 068
- **严重度**: S4（探针说谎：名义上"已强制"的文件系统逃逸 oracle 在默认流程中永远不可能报 ESCAPE——与 F-011 sock-abstract 硬编码 PASS 同类定级；不直接破坏隔离，挂载约束另有宿主侧 mounts-workspace-only 探针独立看守，故不拔高到 S2）
- **攻击面**: E2（guest_script oracle）——E2 既往覆盖了"flag 路径伪造/在挂载内/PATH 劫持"，从未问"谁创建 flag"
- **发现时间**: 2026-11-22T05:29:28Z
- **发现者会话**: night-auditor-v5（R18 第四次收敛判词轮）
- **状态**: 待修复

## 复现（必须）

```sh
# 1) 零操作静态事实：全仓唯一提到旗标文件名的产品代码是"检查"侧，没有任何"放置"侧
grep -rn 'escape-flag' crates scripts --include=*.rs --include=*.sh
#   → 仅 crates/creance/src/main.rs:360  let flag = format!("{}.escape-flag", environment_dir(&profile));
#     （传给 guest_script 作 FLAG= 判据；无 fs::write / File::create / touch，scripts/ 零命中）
git log -S'escape-flag' --oneline -- crates
#   → 69bce85（探针套件首提交）唯一一次引入，此后从未有放置代码

# 2) 动态复现：真实 guest_script() 渲染 + 真实 environment_dir() 推导，宿主上直接执行
#    （guest 视角 = 宿主全盘可见 = 最大逃逸态）
cd harness/tools/r18-flag-oracle && cargo run > /tmp/r18-oracle.out 2>&1; echo RC=$?
```

- **期望**: 被宣称"已强制"的 oracle 在隔离失效时能报 ESCAPE——即 `creance escape-test`（或 setup/up）应在宿主放置 `<environment_dir>.escape-flag`（挂载外的兄弟路径），guest 能读到即 ❌。
- **实际**（RC=0，三场景观测与预测全一致）:
  ```
  [P] oracle path checked by the probe = /tmp/r18-flag-oracle-<pid>/ws.escape-flag
  [S1 no-flag, host-wide visibility] observed="PROBE fs-flag-readable PASS" ... MATCH
  [S2 ESCAPE-BRIEF location]         observed="PROBE fs-flag-readable PASS" ... MATCH
  [S3 code location]                 observed="PROBE fs-flag-readable ESCAPE" ... MATCH
  ```
  S1 = 产品默认流程（无人放置旗标）：即便脚本运行环境能看见宿主全部文件，探针仍报 PASS。只有 S3（有人手工在**代码检查的那个路径**放置旗标）oracle 才有牙；而唯一提到放置的文档 ESCAPE-BRIEF 指示的是另一个路径（S2，见 F-069）。

声明面（均为现在时"已强制/Enforced live"）：
- README.md:71-72 "Enforced live: … with a VM the guest probes — filesystem flag oracle, …"；README.md:89-90 "Live-verified on both: … escape-test green on every enforced layer"（该层的"绿"是空真）
- docs/QUICKSTART.md:84-87 "guest 的文件系统旗标、… 探针均已强制"
- ROADMAP.md:43 "VM 内（已强制。… fs-flag-readable 是旗标 oracle"
- crates/creance/src/main.rs:357 注释 "The flag file on the host is the oracle."；escape.rs:310-311 "A flag file placed on the host is the escape oracle"

## 根因猜测

crates/creance/src/main.rs:356-368 `cmd_escape_test()` 只**推导**旗标路径（:360）并把它注入脚本 `FLAG=`（escape.rs:322-330），全仓无对应的放置步骤（69bce85 首提交即如此）。探针判据 `[ -f "$FLAG" ]` 在文件不存在时恒走 PASS 臂——与 R13 E5 裁定删除的 numeric-proxy-endpoint（"两臂恒 Contained 的空探针"）同构：检查存在但 oracle 前提从未成立。

为什么 18 轮未发现：E2 行（attack-surfaces.md:56）覆盖面是"flag 路径伪造（D3）/flag 在挂载内/PATH 劫持"，全部假设旗标已就位；F-064/R15 [EQ1] 裁判在 FLAG 存在/不存在两世界下验证**发射块**逐字节等价——测的是脚本行为，不是"谁创建 FLAG"；门禁与 r14 [A]/[E] 只看 id 是否在场/有回答。五层自动化都把"PASS 行到达"当作该探针成立。

影响有界性：挂载约束本身由宿主侧 `mounts-workspace-only` 探针（读实例配置）独立看守，所以本条不是隔离破口；但 fs-flag-readable 是唯一的**行为级**文件系统证人（mounts-workspace-only 是配置级）——配置与实际挂载脱节的情形（F-010 先例）下，唯一能抓到它的探针目前是哑的。

## 未验证想法

- 真实 VM 内运行（Lima vz / QEMU）：guest 内是否存在与宿主同名的 `<environment_dir>` 绝对路径——本机零 VM 时长，未实测；不影响结论（文件从未被创建，任何 guest 路径下 `[ -f ]` 都为假）。
- 若修复为"escape-test 运行前放置、运行后删除"，需同时考虑 environment_dir 在 `environment.json` 缺失时 fallback 为 `<profile>-workspace`/`-downloads` 的情形旗标落点是否仍在挂载之外。

## 建议修复方向（供第二天的人参考，非结论）

cmd_escape_test 在跑 guest 脚本前于宿主写入 `<environment_dir>.escape-flag`（随机内容），跑完删除（或改为探针读出内容比对，避免同名伪文件），并加单测断言"运行 guest 脚本时旗标存在"；或在旗标未放置时把 fs-flag-readable 降为 ⏭️ SKIP（不再宣称已强制），与 sock-abstract 诚实 SKIP 的先例对齐，同时修三处声明面。
