# FINDING-084: v0.6.13 修复面守护缺口——F-081 新增的 fw-armed 判据与"标记后置"五例变异全绿；F-078/F-079 残留五例变异仍全绿

- **编号**: 084
- **严重度**: S5（质量：同 F-076/078/079 类——修复面不可被 CI 守住；F-082 正是在这一缺口里带着 CI 全绿发版的）
- **攻击面**: H1 / a24b26b 全部修复面
- **发现时间**: 2026-11-22T07:20Z
- **发现者会话**: r22-auditor（R22 第八次收敛判词轮）
- **状态**: 已修复（main-session，实机复验）

## 复现（必须）

```sh
sh harness/tools/r22-negative-controls/run.sh   # 证据 harness/tools/r22-negative-controls/evidence.log（md5sum -c 全 OK）
```

v0.6.13 实测（cp 备份 → perl 注入 → grep -c 前后计数 → cargo test → 还原）：

```
守住（test-RC=101）: NC-R NC-R2 NC-073q NC-073l NC-074 NC-074b NC-074c NC-RO（F-076 回归）
                     NC-F2（place_oracle_flag 恒真） NC-CLd NC-CLx（wire 严格 CL） NC-NODE（node 钉值改） NC-DIG（Lima digest 改） NC-URL（回滚滚动 release/ URL）
全绿（test-RC=0）:
  F-081  NC-FW    main.rs  删 `|| !fw_ok` 分支
  F-081  NC-FW2   main.rs  fw 探针行 → 无条件 `echo fw-armed`
  F-081  NC-MK    main.rs  在出口守门之前调用 mark_provisioned（标记提前写）
  F-081  NC-MK2   qemu/mod.rs  vm::up 的 mount-ok 分支内写标记（回到 v0.6.12 形态）
  F-081  NC-MP    qemu/mod.rs  mark_provisioned 不落盘却返回 true
  F-078  NC-F     main.rs:360  调用点 `flag_placed = { place_oracle_flag(..); true }`
  F-079  NC-TE    serve.rs:77  workbench 不再拒 Transfer-Encoding
  F-079  NC-NOCK  provision.rs:145  `if [ -n "$CREANCE_NODE_SHA256" ]` → `if false`（校验整段跳过）
  F-079  NC-NOCK2 provision.rs:146  `sha256sum -c - … || rm -f …` → `|| true`（校验失败照装）
  F-079  NC-DIG2  lima.rs:37  "digest" 键 → "digestX"（Lima 不认 = 不校验）
```

- **期望**: F-081/078/079 各自"建议修复方向"列出的行为在注入后至少一条测试变红。
- **实际**: 十例全绿。provision.rs 新断言只做子串存在性（`sha256sum -c -` 与两个钉值仍在，跳过/吞失败不影响）；lima.rs 新断言只检查 digest 字符串在 YAML 里，不检查它挂在 `images[0].digest` 键下；F-078 的抽取让 place_oracle_flag 可测，但调用点 → oracle_ready 的接线仍不可测；cmd_up 的探针 shell、fw_ok 判定、标记写入时机均无任何测试经过。

## 根因猜测

crates/creance/src/main.rs:680-797 cmd_up 与 :340-430 cmd_escape_test 是 I/O 编排大函数，判据（探针文本、输出判读、标记时机）内联其中；crates/creance-vm/src/provision.rs:241-249、lima.rs:278-291 的新测试是 contains 断言。

## 未验证想法

- 无。

## 建议修复方向（供第二天的人参考，非结论）

把 up 守门拆成纯函数 `egress_verdict(out) -> Result<(), Reason>` 与 `egress_probe_script()`，对后者至少做"脚本在无特权 sh 下对 fake iptables 的输出产出 fw-armed"的可执行测试（PATH 注入假 iptables 不可行——探针重置 PATH，正说明需要 F-082 的替代判据）；标记时机由"守门通过才返回可标记"的类型约束承载；NOCK/NOCK2 用执行渲染片段对坏 tarball 断言被删；DIG2 解析 YAML 断言 `images[0].digest`；TE 加 serve 端到端 400 用例。
