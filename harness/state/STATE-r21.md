# STATE-r21 — 第七轮收敛判词轮（R21）：**不收敛**

- 基线：main = v0.6.12（tag daece7f），分支 audit/r21；`sh scripts/ci.sh` RC=0（harness/tools/r21-baseline/ci.log）
- 判词：**本轮有 4 条新发现（078–081），按任务书"有新发现 → 立案不收敛"，不发收敛判词。**
- 未改 crates/、scripts/、docs/；变异全部 cp 备份 → grep -c 计数 → md5 还原核验。

## A) R20 修复复核

| 项 | 结论 | 证据 |
|---|---|---|
| F-076 restrict 标记测试（NC-R/NC-R2） | 已守住：变异即红 | r21-negative-controls/evidence.log |
| F-076 QEMU /32 表断言（NC-073q） | 已守住 | 同上 |
| F-076 Lima /32 表断言（NC-073l） | 已守住 | 同上 |
| F-076 oracle_ready=false 单 SKIP（NC-074/074b/074c） | 已守住 | 同上 |
| F-076 runcmd 调序断言（NC-RO） | 已守住 | 同上 |
| F-076 调用方 flag_placed 恒真（NC-F） | **未守住 → F-078** | 同上 |
| F-077 restrict 文档面对齐 | 已修复：qemu/mod.rs、runner 注释、ROADMAP 与实现一致 | 代码阅读 |
| F-077 首次供给重启提示 | 已修复：实机首次 up 打印提示并写 provisioned | r21-restrict-mask/evidence/up1.log |
| 标记写入路径（NC-M：删写入） | **未守住 → F-079**；写入时机早于出口守门 → **F-081** | evidence.log、r21-restrict-mask |
| 标记生命周期：setup 重建 | 清理正确：重建前 present → 后 absent（实机） | r21-restrict-mask/evidence/rebuild.log |
| 标记生命周期：delete / rename | 实例目录整删；实例名由工作区路径派生，无 rename 继承路径（代码阅读） | qemu/mod.rs |
| we_started=false 复用 VM | 出口守门失败时无条件 stop 属有意 fail-closed，未见误杀健康复用 VM 的路径 | main.rs:745-770 |
| restrict=on 下第一道防线失效可观测性 | **不可观测 → F-081**（up 守门与 escape-test net-* 全绿） | r21-restrict-mask/evidence/mask.log |
| 门禁矩阵回归 + 正控 | NC2/NC3/NC5/NC6v 全红，正控四文件 OK | r21-gate-matrix/evidence.log |
| 裁判双跑 r14/r15 | r14 RC=0 ×2 md5=2ecbd0c1；r15 RC=0 ×2 md5=965e444c | r21-judges/evidence.log |

## B) v0.6.11..v0.6.12 邻接面

- wire 下沉：gate/workbench 走 strict_content_length；egress.rs 仍自带解析、接受重复相同 CL——与 wire.rs"tunnel 读者共用/一致拒绝"注释不符；严格 CL、拒 TE 注入全绿 → F-079。
- sha256 常量：node x64/arm64 钉值删改或删校验注入全绿 → F-079；Lima digest 钉在滚动 `release/` URL，已证与 release-20260926 目录值不同 → F-080。
- QEMU 镜像：运行时取 SHA256SUMS 校验，无钉值问题。

## 新发现

| 编号 | 严重度 | 一句话 |
|---|---|---|
| 078 | S5 | F-076 修复漏一例：main.rs flag_placed 恒真仍 cargo test 全绿 |
| 079 | S5 | v0.6.12 新增面（严格 CL、拒 TE、node sha256、Lima digest）七例注入全绿；wire.rs 注释不实 |
| 080 | S4 | Lima digest 钉在滚动 release URL：Ubuntu 刷新后 macOS setup 全部 fail-closed |
| 081 | S4 | restrict=on 武装后 guest 防火墙全放行仍 up/escape-test 全绿；标记写在出口守门前，失败的 up 也补写标记 |

## R22 建议

复核 078–081 修复（每项注入验红）；081 修复后实机重跑 r21-restrict-mask（期望 up#2 报警）；080 修复后在旧 release 目录值下验证 setup 行为。
