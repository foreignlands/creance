# STATE-r22 — 第八次收敛判词轮（R22）：**不收敛**

- 基线：main = v0.6.13（tag a24b26b），分支 audit/r22；`sh scripts/ci.sh > ci.log 2>&1; RC=$?` → **RC=0**（172 passed / 0 failed；harness/tools/r22-baseline/）
- 判词：**本轮有 4 条新发现（082–085），其中 082 使 v0.6.13 的 Linux `creance up` 100% 失败。按任务书"有新发现 → 立案不收敛"，不发收敛判词，审查循环不停轮。**
- 未改 crates/、scripts/、docs/；变异全部 cp 备份 → grep -c 注入前后计数 → md5sum -c 还原核验（全 OK）；裁判工具 Cargo.lock 的在线运行漂移已 `git checkout --` 还原。

## A) F-078..081 修复复核

| 核验点 | 结论 | 证据 |
|---|---|---|
| F-076 回归八例（NC-R/R2/073q/073l/074/074b/074c/RO） | 守住：全红 | r22-negative-controls/evidence.log |
| F-078 place_oracle_flag 本体恒真（NC-F2） | 守住 | 同上 |
| F-078 调用点 flag_placed 恒真（NC-F） | **未守住 → F-084** | 同上 |
| F-079 wire 严格 CL（NC-CLd/CLx） + gate 重复 CL→400 | 守住 | 同上 |
| F-079 workbench 拒 TE（NC-TE） | **未守住 → F-084**（serve 未补用例） | 同上 |
| F-079 node 钉值改（NC-NODE） | 守住 | 同上 |
| F-079 node 校验跳过 / 吞失败（NC-NOCK / NC-NOCK2） | **未守住 → F-084** | 同上 |
| F-079 Lima digest 值改（NC-DIG） | 守住 | 同上 |
| F-079 Lima digest 键失效（NC-DIG2） | **未守住 → F-084** | 同上 |
| F-080 回滚滚动 release/ URL（NC-URL） | 守住；dated release-20261017 SHA256SUMS 与钉值一致 | 同上；r22-lima-digest/evidence.txt |
| F-081 删 fw_ok 分支（NC-FW）/ 探针恒 armed（NC-FW2） | **未守住 → F-084** | 同上 |
| F-081 标记提前写（NC-MK）/ 回 vm::up（NC-MK2）/ 假落盘（NC-MP） | **未守住 → F-084** | 同上 |
| F-081 标记写点在所有失败分支之后（代码阅读） | 成立：main.rs:789 在 tcp/icmp/fw 三判与 Err 分支全部 return 之后、仅 code==0 路径 | main.rs:739-797 |
| F-081 fw-armed 实机行为 | **恒 fw-down → F-082**：无特权 uid 1000 + PATH 无 /usr/sbin；Linux 每次 up 失败停机，标记永不写，restrict=on 永不武装 | r22-fw-armed/evidence/up1,up2,race.log |
| fw-armed 解析正确性 / 误报面 | legacy 与 nft 的 `-L` 首行格式一致，无后端误报；但只看策略：DROP+ACCEPT 全放行判 armed **→ F-083** | r22-fw-armed/netns.log P1–P5 |
| restrict 文档面续扫 | 代码注释（qemu/mod.rs:5、:305、runner.rs:140）与 v0.6.13 实现一致；README/ROADMAP/QUICKSTART 无 restrict 宣称；CHANGELOG 0.6.10–0.6.13 缺失 **→ F-085** | grep |
| 复用路径 we_started=false | mount-missing 时不停复用 VM（qemu/mod.rs:289/296 受 we_started 约束）；但出口守门失败无条件 stop_vm——叠加 F-082，任何对运行中健康 VM 的 up 都会停掉它（记入 F-082） | 代码阅读 |
| 标记生命周期 delete / setup 重建 / rename | 无变化（v0.6.13 只改写入时机）：重建与删除整删实例目录；实例名由工作区派生，无 rename 继承；R21 实机已证重建清理 | R21 rebuild.log + 代码阅读 |
| 门禁矩阵 + 正控 | POS RC=0；NC-A/B/1/2/3/5/6v 全 RC=1；md5 四文件 OK | r22-gate-matrix/evidence.log |
| 裁判双跑 | r14 RC=0 ×2 md5=2ecbd0c1；r15 RC=0 ×2 md5=965e444c（与 R21 一致） | r22-judges/evidence.log |

## B) v0.6.12..v0.6.13 全量 diff

逐文件过（gate.rs、wire.rs、lima.rs、provision.rs、qemu/mod.rs、vm.rs、escape.rs、main.rs）：
- wire：parse_header_block / strict_content_length 调用方只有 gate.rs:462 与 serve.rs:70；egress 响应侧自有解析，wire.rs 注释已如实改写；无遗漏调用方。
- sha256 常量：node x64/arm64 与 Lima arm64 钉值与上游一致（Lima 已核 dated 目录）。
- provisioned 写入：唯一写点 qemu::mark_provisioned（经 vm::mark_provisioned，macOS no-op）← main.rs:789；runner.rs:419 为测试内写入。

## 新发现

| 编号 | 严重度 | 一句话 |
|---|---|---|
| 082 | S4 | fw-armed 探针以无特权用户 + PATH=/usr/bin:/bin 跑 iptables -L 恒 fw-down：Linux 每次 up 完整供给后失败停机，restrict=on 永不武装 |
| 083 | S4 | fw-armed 只看 OUTPUT 默认策略：DROP + ACCEPT 全放行规则仍判 armed |
| 084 | S5 | v0.6.13 修复面十例变异全绿（F-081 五例 + F-078/079 残留五例） |
| 085 | S5 | CHANGELOG 停在 0.6.9，0.6.10–0.6.13 零条目 |

## R23 建议

1. 082 修复后实机：全新 setup → up#1 RC=0 写标记 → up#2 netdev 含 restrict=on；再跑 R21 的 r21-restrict-mask（期望 up#2 报警）。
2. 083：在 guest 内造 DROP+ACCEPT 形态，期望 up 拒绝。
3. 084 十例重跑 r22-negative-controls，期望全红。
