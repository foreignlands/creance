# FINDING-117: F-111 外壳钉/行为断言可绕：闭包形参对调 `|i, p|`（字面 `vm::stop_vm(p, i)` 不变）、stop 包进永不调用的闭包、`vm::guest_script_ok` 前缀字面 canned runner、fake runner 只做 `egress-armed` 子串检查

- **编号**: 117
- **严重度**: S5（质量：守护/测试强度不足，需代码变更才可触发；无运行时可达路径）
- **攻击面**: F-111 修复面（crates/creance-vm/src/gateprobe.rs `verify_and_mark` + `verify_and_mark_shell_is_pinned`）
- **发现者会话**: r31-auditor
- **状态**: 已修复（main-session，实机复验）

## 机理

外壳钉只做文本：`vm::stop_vm(p, i)` 字面不约束闭包形参的绑定顺序（`|i, p|` 使字面保留但实参对调）；`let _ = || vm::stop_vm(p, i);` 保留字面与 `vm::` 计数但从不调用；`verify_and_mark_with(profile, instance, vm::guest_script` 是前缀子串，`vm::guest_script_ok,` 同样满足，而 vm.rs 里可新增一个 canned 函数（vm.rs 不禁 `Ok(`/字面量）。RefCell 行为断言只覆盖 `verify_and_mark_with`，外壳本身没有行为测试；fake runner 对注入脚本只断言 `contains("egress-armed")`，一行注释即满足。

## 复现

```sh
git worktree add --detach $HOME/r31-wt v0.6.23   # worktree 放 $HOME，勿放 /tmp
cd harness/tools/r31-negative-controls
CREANCE_REPO=$HOME/r31-wt ONLY="NC-WRAPparam NC-WRAPdead NC-WRAPalias NC-GPscript3" python3 run.py   # 用例见 cases.py
```

期望：每个用例至少一项测试或 clippy 红。实际（fmt+cargo test --workspace --locked+clippy -D warnings；裁判双跑，见 logs/ 与 logs-ref/；md5 还原 OK）：

| 用例 | 注入 | 测试 | 后果 |
|---|---|---|---|
| NC-WRAPparam | 外壳 `\|p, i\| {` → `\|i, p\| {` | 绿×2 | 拒绝时 stop_vm(instance, profile)——停错/不停 VM |
| NC-WRAPdead | `let _ = vm::stop_vm(p, i);` → `let _ = \|\| vm::stop_vm(p, i);` | 绿×2 | 拒绝时 VM 永不停止 |
| NC-WRAPalias | vm.rs 新增 `guest_script_ok` 恒返回 canned 探针；外壳改传 `vm::guest_script_ok` | 绿×2 | 不进 guest 探测即铸令牌、写 marker |
| NC-GPscript3 | 探针脚本 → `concat!("# egress-armed\necho tcp-", "blocked; …")` | 绿×2 | canned 探针，fake runner 子串检查被注释满足 |

## 建议

外壳钉改为整函数体 trim 后 verbatim 相等（含闭包形参与 `;` 边界）；外壳增加 cfg(test) 可替换的行为测试；fake runner 断言 script 与 `egress_probe_script(nat_allow_hosts())` 全等而非子串。
