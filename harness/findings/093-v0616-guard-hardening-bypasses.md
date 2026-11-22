# FINDING-093: v0.6.16 守护加固 9 例变异仍全绿——marker 计数可被 `use … as`/括号路径绕过、Ok/Err 位置守护可被臂重排绕过、vm.rs 计数不钉位置、`write_marker` 直调无守护、"path-prefix gate 会被抓"不成立、stamp 唯一写点只认 `> /run`、"apply 后无 netfilter"只认 `iptables` 字样

- **编号**: 093
- **严重度**: S5（质量：同 F-076/078/079/084/087/091 类——CHANGELOG 0.6.16 F-091 宣称的守护语义不被 CI 守住）
- **攻击面**: H1 / F-091 修复面
- **发现时间**: 2026-11-22T14:30Z
- **发现者会话**: r25-auditor（R25 第十次收敛判词轮）
- **状态**: 待修复

## 复现（必须）

```sh
CREANCE_REPO=$PWD sh harness/tools/r25-negative-controls/run.sh   # 证据 run.log；每例 cargo 输出 logs/<case>.log
```

规程：cp 备份 → perl 注入 → grep -c 前后计数证明落地 → `cargo test --locked -q -p <crate>` → cp 还原 → md5sum -c（6 文件全 OK）。

变红（守护有效，19 例）：任务书点名的 NC-MKalias（`&*profile` 第二调用）、NC-MK3（Err(reason) 第二调用）、NC-MK4m（marker 移入探针 `Err(e)` 臂）、NC-MK2（qemu/mod.rs mount-ok 调用）、NC-MK5（vm.rs `up` 第三处调用）、NC-MP2（`creance-mk-` 前缀 gate）、NC-STAMPf（第二条 `> /run/egress-armed`）、NC-RST4（restart 后 `iptables -P OUTPUT ACCEPT`）、NC-NOCKb（sha 条件 `&& false`）、NC-NAT1/NAT2（NAT 表多一项）；F-090 canonical 集：NC-SAVEICMP（删 save 形 icmp）、NC-QUOTE（去单引号）、NC-HEXP（save 形去 /32）、NC-SEL（选行收窄）、NC-NOX（`-vxF`→`-vF`）、NC-WANT（不读 rules.v4）、NC-CTNEW（白名单加 NEW,ESTABLISHED）。

**全绿（无守护，9 例）**：

| 用例 | 注入 | 落空的 CHANGELOG 0.6.16 宣称 / 后果 |
|---|---|---|
| NC-MKuse | Err(reason) 臂内 `{ use creance_vm::vm::mark_provisioned as arm_restrict; let _ = arm_restrict(&profile, &instance); }` | "counts the bare name (aliases/Err-arms/second sites fail)"——针是 `mark_provisioned(`，`use … as` 改名后调用不含该针；探针判 fw-down 时仍写 marker |
| NC-MKparen | Err(reason) 臂 `let _ = (creance_vm::vm::mark_provisioned)(&profile, &instance);` | 同上：`mark_provisioned)(` 不含 `mark_provisioned(` |
| NC-MKswap | Ok(()) 臂与 Err(reason) 臂互换顺序，marker 从 Ok 臂移入 Err(reason) 臂 | "pins the call between Ok(()) and Err(e)"——位置守护比较字节偏移，臂重排后 Err(reason) 位于 Ok(()) 与 Err(e) 之间，恒满足；marker 只在 verdict 失败时写 |
| NC-MK6 | vm.rs `mark_provisioned` 分派体改为 `false`，在 vm.rs `up` 里 `qemu::up` 返回 0 后直调 `crate::qemu::mark_provisioned` | "vm.rs def+dispatch"——只计 2 次不钉位置；marker 回到 F-081 前的"verdict 前写" |
| NC-WM | qemu/mod.rs `up` 的 mount-ok 臂 `let _ = write_marker(&dir);` | creance-vm 守护只数 `mark_provisioned(`；`write_marker` 抽层后可绕开整套调用点守护直接写 marker |
| NC-MP3 | `write_marker` 开头 `if !dir.starts_with(std::env::temp_dir()…) { return true; }` | "runs under two different dir names so a path-prefix gate would be caught"——两目录同在 temp_dir 下，路径前缀 gate（产品目录 `~/.creance/...` 恒 true 不写盘）不被抓 |
| NC-STAMPf2 | ExecStartPost 后加 `ExecStartPost=/bin/sh -c 'echo ":OUTPUT DROP [0:0]" >/run/egress-armed'` | "the ExecStartPost stamp is the only redirect into /run/egress-armed"——计数针 `> /run/egress-armed` 含空格，`>/run/…` 不计；伪盖章覆盖真盖章 |
| NC-STAMPf3 | 同上改 `… \| tee /run/egress-armed` | 同上：非重定向写点不计 |
| NC-RST5 | `systemctl restart egress-lock.service` 后加 `nft flush ruleset` | "nothing after the apply leg touches netfilter at all"——断言只查 `iptables` 子串；nft 直接清空 live 规则集 |

## 根因

- `crates/creance/src/main.rs:802-826`（`up_gate_tests::provisioned_marker_only_after_verdict`）：字面针计数 + 字节偏移位置比较，不解析调用实体，不钉臂顺序。
- `crates/creance-vm/src/qemu/mod.rs:564-580`（`mark_provisioned_is_called_only_from_the_cli_crate`）：只计 `mark_provisioned(`，不计 `write_marker(`，不钉 vm.rs 调用点位置。
- `crates/creance-vm/src/qemu/mod.rs:543-557`（`write_marker_writes_once_then_refuses`）：两目录名同父目录，只区分名字前缀。
- `crates/creance-vm/src/provision.rs:339-347`：`matches("> /run/egress-armed").count() == 1` 与 `!after_apply.contains("iptables")` 均为单拼写针。

## 修复建议（仅建议，审查员不修）

把守护从"源码字面"移到行为：marker 写入经由一个只在 verdict Ok 时可构造的类型（如 `Verified` token 参数）；`write_marker` 测试在非 temp 父目录（或 `instance_dir` 真实路径形）跑；stamp 写点改为"去掉 ExecStartPost 真行后全文不含 `egress-armed`"；apply 后片段断言为精确的期望尾部（逐字节相等），而非黑名单子串。
