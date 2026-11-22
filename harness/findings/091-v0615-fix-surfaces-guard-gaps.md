# FINDING-091: v0.6.15 修复面 12 例变异仍全绿——marker 守护是字面针（移入 `Err(e)` 臂/`&*profile` 别名/无 `&` 调用/vm.rs 调用全过）、provision 断言只证"在场"不证"唯一/无后继"、hosts_re 拼接与 NAT 常量无行为守护

- **编号**: 091
- **严重度**: S5（质量：同 F-076/078/079/084/087 类——修复面不可被 CI 守住）
- **攻击面**: H1 / F-087 修复面
- **发现时间**: 2026-11-22T13:55Z
- **发现者会话**: r24-auditor（R24 第十次收敛判词轮）
- **状态**: 待修复

## 复现（必须）

```sh
sh harness/tools/r24-negative-controls/run.sh                         # 证据 evidence.log；每例 cargo 输出 logs/<case>.log
ONLY="NC-PRB5b NC-NOCK4b" sh harness/tools/r24-negative-controls/run.sh  # evidence-rerun.log（PRB5/NOCK4 首版注入未编译，作废重注）
```

规程：cp 备份 → perl 注入 → grep -c 证明落地 → `cargo test --locked -q -p <crate>` → cp 还原 → md5sum -c（6 文件全 OK）。

变红（守护有效，17 例）：NC-HRE（hosts 不转义）/ICMP（白名单删 icmp）/D32（dst 去 /32）/CTN（conntrack 放行 NEW）/RULES（不查 rules.v4 DROP 策略）/CAT（只读 stamp）/PRB2（恒 fw-armed）/PRB5b（stamp DROP 检查 `|| true`）、NC-MK3（Err(reason) 臂第二调用点）、NC-MP（write_marker 恒 true）、NC-STAMPr（ExecStartPost 尾 `|| true`）/STAMPr2（`ExecStartPost=-`）/RST2（restart 后 `; true`）/RST3（restart 腿加 `#`）、NC-NOCK（sha 条件 `if false`）/NOCK3/NOCK4b（校验后再下载）。等价变异 1 例：NC-MKpost（marker 移到 match 之后——Err 臂均 return，语义等价）。

**全绿（无守护，12 例）**：

| 用例 | 注入 | 后果 |
|---|---|---|
| NC-MK4m | marker 调用从 Ok 臂移到 `Err(e) =>`（探针执行失败）臂 | **任务书点名变异**：探针跑不起来反而写 marker，下次 up 起 restrict=on 并跳过首供给语义。守护只比 `mark > verdict + 首个 "Ok(())"` 的字节位置，Err 臂在 Ok 臂之后，恒满足 |
| NC-MKalias | Err(reason) 臂加 `mark_provisioned(&*profile, &instance)` | **任务书点名变异**（唯一调用点拆两处）：守护按字面针 `mark_provisioned(&profile, &instance)` 计数，别名形不计 |
| NC-MK2 | qemu/mod.rs `mount-ok` 分支加 `let _ = mark_provisioned(profile, instance);` | CHANGELOG 0.6.15 宣称 "a guard rejects `mark_provisioned` call sites inside creance-vm"——守护针是 `mark_provisioned(&`，无 `&` 的调用不计 |
| NC-MK5 | vm.rs `up` 分派在 `qemu::up` 返回 0 后写 marker | vm.rs 不在扫描清单（只扫 qemu/mod.rs、runner.rs、provision.rs）；marker 回到 F-081 前的"守门前写" |
| NC-MP2 | write_marker 开头 `if !dir.contains("creance-mk-") { return true; }` | 写一次语义只在测试 temp 目录形态下被测；产品目录下恒 true 不写盘 |
| NC-STAMPf | 真 ExecStartPost 后再加一条 `printf ":OUTPUT DROP [0:0]\n" > /run/egress-armed` | 断言只证真行"在场"，不证它是唯一/最后一条写 stamp 的命令——伪盖章覆盖真盖章 |
| NC-RST4 | `systemctl restart egress-lock.service` 后加 `/usr/sbin/iptables -P OUTPUT ACCEPT` | restart 腿"在场且未注释"，紧随其后的解除命令无守护 |
| NC-NOCKb | `if [ -n "$CREANCE_NODE_SHA256" ]; then` → `… ] && false; then` | 断言是 `contains("if [ -n \"$CREANCE_NODE_SHA256\" ]")` 前缀，不是整行（0.6.15 宣称 exact line） |
| NC-HRE2 | `egress_probe_script` hosts `.join("\|")` → `.join("")` | 真值表直接喂手写 hosts_re，绕过产品拼接；产品 hosts_re 变 `10\.0\.2\.210\.0\.2\.3`，每次实机 up 都判 fw-down，CI 全绿 |
| NC-NAT1 | `NAT_HOSTS_QEMU` 加 `"8.8.8.8"` | NAT 单源常量无精确钉：rules.v4 渲染与 probe 白名单同步放行外网 /32，测试全绿 |
| NC-LEAK | 第一阶段 `-j ACCEPT$` → `-j (ACCEPT\|LEAK)$` | 后两阶段遮蔽裸 LEAK，但 `-d 10.0.2.2/32 -p icmp -j LEAK` 形放行；真值表无只被该阶段拦住的行 |
| NC-CTN2 | conntrack 豁免去掉 `-j ACCEPT$` 尾锚 | `-m conntrack --ctstate ESTABLISHED -j <任意链>` 被豁免——F-086 "chain jump reads fw-down" 对 conntrack 行失效 |

## 期望

0.6.15 CHANGELOG F-087 条目所列每个修复面（marker 在 verdict Ok 臂内且全文件唯一、creance-vm 内无调用点、write_marker 写一次、exact-line provision 断言、NAT 单源）都应有能让上述变异变红的守护。

## 根因假设

- `crates/creance/src/main.rs:806-826` `provisioned_marker_only_after_verdict`：字面针计数 + "首个 Ok(()) 之后"字节位置——不是"位于 verdict match 的 Ok 臂块内"。
- `crates/creance-vm/src/qemu/mod.rs:561-580`：针 `mark_provisioned(&`，扫描清单漏 vm.rs。
- `crates/creance-vm/src/provision.rs:330-347`：`contains` 在场断言，无唯一性/后继约束；sha 条件为前缀。
- `crates/creance/src/escape.rs` 真值表测试只测 `fw_probe_fragment(<手写 hosts_re>)`，不经 `egress_probe_script(nat_allow_hosts())`；`crates/creance-vm/src/vm.rs` NAT 常量无精确值断言。
