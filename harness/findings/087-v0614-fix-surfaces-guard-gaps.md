# FINDING-087: v0.6.14 修复面 13 例变异仍全绿——probe 语义未被执行测试、marker 源码序守护只比"首次出现"位置、mark_provisioned 写盘、stamp 内容、restart 腿、node 校验门条件均无行为守护

- **编号**: 087
- **严重度**: S5（质量：同 F-076/078/079/084 类——修复面不可被 CI 守住）
- **攻击面**: H1 / F-084 修复面
- **发现时间**: 2026-11-22T13:10Z
- **发现者会话**: r23-auditor（R23 第九次收敛判词轮）
- **状态**: 待修复

## 复现（必须）

```sh
sh harness/tools/r23-negative-controls/run.sh   # 证据 evidence.log；每例 cargo 输出在 logs/<case>.log
```

规程：cp 备份 → perl 注入 → grep -c 证明落地 → `cargo test --locked -p <crate>` → cp 还原 → md5sum -c（9 文件全 OK）。跑两遍，结果一致。

变红（守护有效，30 例）：NC-R/R2/073q/073l/074/074b/074c/RO/F/F2/SIG、NC-CLd/CLx/TE/TE2/CLs、NC-NODE/NOCK2/DIG/DIG2/URL、NC-EXP（删 ExecStartPost）/STAMP（stamp 不含规则行）/RST（restart→start）、NC-FW（verdict 删 fw_ok）/VOK（verdict 恒 Ok）/PRB（probe 恒 echo fw-armed）/PRB4（probe 删裸 ACCEPT 检查）、NC-MK（marker 移到 probe 调用前）。

**全绿（无守护，13 例）**：

| 用例 | 注入 | 后果 |
|---|---|---|
| NC-PRB2 | probe `else echo fw-down` → `else echo fw-armed` | 任何 stamp（含缺失）都判 armed——"probe 改恒输出"的等价形态 |
| NC-PRB3 | `! grep -qxF '-A OUTPUT -j ACCEPT'` → 去掉 `!` | F-083 判据反转：只有裸 ACCEPT 存在才判 armed |
| NC-PRB5 | `grep -q '^:OUTPUT DROP'` 包成 `{ …; || true; }` | 策略行判据失效（stamp 存在即 armed） |
| NC-MK3 | `mark_provisioned` 插进 `if let Err(reason) = egress_verdict` 分支首行 | verdict 失败照样写 marker，下次 up 起 restrict=on 遮蔽——F-081 原形态 |
| NC-MK4 | `mark_provisioned` 插进 guest_script `Err(e)` 分支 | 同上（探针执行失败也武装） |
| NC-MK2 | qemu/mod.rs `mount-ok` 分支内写 marker（在 verdict 之前，且在 vm::up 内） | 同上，正是测试注释声称防住的"inside vm::up" |
| NC-MP | `mark_provisioned` 不写文件、返回 true | restrict=on 永不武装，"供给完成"提示照打 |
| NC-STAMPf | ExecStartPost 末尾追加 `; printf ":OUTPUT DROP [0:0]\n" > /run/egress-armed` | stamp 被伪造为纯策略行，F-083 防线失效 |
| NC-STAMPr | ExecStartPost 追加 `|| true; true` | stamp 生成失败被吞（unit 不再 failed） |
| NC-RST2/RST3 | `systemctl restart egress-lock.service` 追加 `; true` / 整行注释掉 | 注释后 apply 腿消失；测试只查子串，注释行仍含该子串 |
| NC-NOCK | `if [ -n "$CREANCE_NODE_SHA256" ]` → `if false` | node tarball 校验整段跳过 |
| NC-NOCK3 | 校验后重新 curl 覆盖 tarball 再解压 | 校验结果被绕过（稍做作，记录） |

NC-RMF（main.rs 在 guest_script 前删 flag）全绿属预期：v0.6.14 由 guest_script 内部落盘，调用方删除已无效——不计入。

- **期望**: F-084 修复声称"probe/verdict 全分支单测""源码序守护 marker 在 verdict 之后""provision ExecStartPost/node sha256 rm 门断言"——上述注入应至少有一个测试变红。
- **实际**: 
  - escape.rs:926 `egress_probe_reads_only_unprivileged_evidence` 只做 `contains` 子串断言，从不执行探针；verdict 有分支测试，probe 没有（PRB2/3/5）。
  - main.rs:797 `provisioned_marker_only_after_verdict` 只比 `find("escape::egress_verdict")` 与 `find("creance_vm::vm::mark_provisioned")` 的首次出现偏移，外加一个精确字面的"不得紧贴 vm::up"——失败分支里的写入、或 creance-vm 内部 `mark_provisioned(profile, instance)`（无 `creance_vm::vm::` 前缀）都不可见（MK2/3/4）；mark_provisioned 本身无测试（MP）。
  - provision.rs:322 `armed_stamp_is_root_written_from_live_rules` 断言 ExecStartPost 前缀、`> /run/egress-armed`、`^:OUTPUT|^-A OUTPUT` 子串存在；不约束 stamp 是否被覆盖/吞错（STAMPf/r）；restart 腿与 node 校验门的断言同为子串（RST2/3、NOCK）。

## 根因猜测

修复后的守护仍以源码子串为主，没有把 shell 片段放进可执行夹具（sh + 假 stamp 文件）跑真值表，也没有把 marker 写入点做成"唯一调用点 + 仅成功路径"的结构性约束。

## 建议修复方向（供第二天的人参考，非结论）

probe 的 fw 行在测试里用 sh + 临时 stamp 跑真值表（缺失/策略 ACCEPT/裸 ACCEPT/限定 ACCEPT/正常）；marker 写入断言改为"全文件唯一一次出现 + 位于 verdict Ok 之后的成功路径"，并对 creance-vm 全 crate 断言 mark_provisioned 无内部调用；provision 片段改为整行精确匹配（非注释行）。
