# FINDING-111: F-104 注入缝外壳未测：prod `verify_and_mark` 的 runner/stop 闭包与被钉函数体的实参全可换形——canned runner、stop 变 noop、stop/probe 实参对调、Ok 臂条件化全绿

- **编号**: 111
- **严重度**: S5（质量：守护/测试强度不足，需代码变更才可触发；无运行时可达路径）
- **攻击面**: F-104 修复面（crates/creance-vm/src/gateprobe.rs:141-182）
- **发现者会话**: r30-auditor
- **状态**: 待修复

## 机理

行为测试与函数体钉全部落在 `verify_and_mark_with` 上；真正被 main.rs 调用的 `verify_and_mark`（gateprobe.rs:141-145）只是一层把 `vm::guest_script` 与 `|p, i| { let _ = vm::stop_vm(p, i); }` 传进去的外壳，**没有任何钉或测试**。同时函数体钉只数形状（`stop(`==2、`mark_provisioned(`==1、禁 canned 子串），不钉实参：fake stop 闭包忽略参数，所以 `stop(instance, profile)` 也绿；fake runner 忽略脚本参数，所以 split-literal canned 探针也绿；`mark_provisioned(` 计数不拦在其前面加短路条件。

## 复现

```sh
CREANCE_REPO=$HOME/r30-wt ONLY="NC-WRAPfake NC-WRAPnostop NC-WRAPswap NC-GPstopswap NC-GPscript2 NC-GPtmpgate" python3 harness/tools/r30-negative-controls/run.py   # worktree 放 $HOME（git worktree add --detach $HOME/r30-wt v0.6.22）；用例见 harness/tools/r30-negative-controls/cases.py
```

期望：每个用例至少一项测试或 clippy 红。实际：

| 用例 | 注入 | 测试（fmt+cargo test --workspace+clippy -D warnings；裁判双跑） | 后果 |
|---|---|---|---|
| NC-WRAPfake | 外壳的 `vm::guest_script` → `\|_p,_i,_s\| Ok(concat!("tcp-","blocked\nicmp-",…).to_owned())` | 绿×2 | guest 内不探测，恒铸令牌→marker 武装（F-104 NC-GPcanned 在外壳复发） |
| NC-WRAPnostop | 外壳 stop 闭包体 → `let _ = (p, i);` | 绿×2 | 每次拒绝都不停 VM（拒绝时防火墙未生效的 VM 继续跑） |
| NC-WRAPswap | `vm::stop_vm(p, i)` → `vm::stop_vm(i, p)` | 绿×2 | 停的是不存在的实例，同上 |
| NC-GPstopswap | 函数体两处 `stop(profile, instance)` → `stop(instance, profile)` | 绿×2 | 同上（实参不钉，fake stop 忽略参数） |
| NC-GPscript2 | `&egress_probe_script(vm::nat_allow_hosts())` → `concat!("echo tcp-", "blocked; echo icmp-", …)` | 绿×2 | canned 探针；canned 子串禁被 concat! 拆分绕开（fake runner 忽略脚本） |
| NC-GPtmpgate | Ok 臂 → `Ok(profile.starts_with(&*std::env::temp_dir().to_string_lossy()) && vm::mark_provisioned(…))` | 绿×2 | 行为测试 profile 在 temp_dir 下照写 marker；生产 profile 永不武装（restrict=on 静默失效） |

## 已尝试未通的路（对照红）

已拒：`let out` 遮蔽/`.map(`/字面量 verdict/canned 原串（NC-GPshadow2/GPmap/GPforge/GPcanned 红）；RefCell 计数确实覆盖“拒绝时 stop 被调用一次”。

## 建议

fake runner/stop 应记录收到的 (profile, instance, script) 并断言等于输入与 `egress_probe_script(nat_allow_hosts())`；外壳 `verify_and_mark` 用 cfg(test) 可替换的模块级 runner 或直接钉外壳全文；Ok 臂整行相等钉。
