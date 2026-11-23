# FINDING-118: F-112 封印仍可铸：扫描表仅 4/18 个 creance-vm prod 文件——vm.rs 内 `mem::zeroed()`、qemu/image.rs 内 `NonNull::dangling().read()` 铸令牌；SAFE 代码 `pub(crate) const VERDICT: fn(..) = egress_verdict;` 导出私有 verdict 全绿

- **编号**: 118
- **严重度**: S5（质量：守护/测试强度不足，需代码变更才可触发；无运行时可达路径）
- **攻击面**: F-112 修复面（crates/creance-vm/src/qemu/mod.rs crate 全域扫描；gateprobe.rs `fn egress_verdict` 行级 pub 禁）
- **发现者会话**: r31-auditor
- **状态**: 已修复（main-session，实机复验）

## 机理

全域扫描只禁 `transmute`/`_sealed` 两个词，`std::mem::zeroed()`、`ptr::read`、`MaybeUninit` 等对 ZST/私有字段结构同样可铸；扫描表是硬编码的 4 文件（vm.rs、qemu/mod.rs、qemu/provision.rs、qemu/runner.rs），而 creance-vm/src 下还有 config/exit_policy/guestprofile/host/lib/lima/paths/pidfile/private/running/tunnel/vmname 及 qemu/image、qemu/seed 共 14 个 prod 文件未扫——CHANGELOG [0.6.23] 写“across every creance-vm prod file”与实现不符。行级 pub 禁只看 `fn egress_verdict` 所在行：在 gateprobe.rs 内加 `pub(crate) const VERDICT: fn(&str) -> Result<EgressVerified, &'static str> = egress_verdict;` 不含 unsafe、不加 pub 到 fn 行、`egress_verdict(` 计数不变，crate 内任何位置可经 `VERDICT(canned)` 取得令牌。

## 复现

```sh
git worktree add --detach $HOME/r31-wt v0.6.23   # worktree 放 $HOME，勿放 /tmp
cd harness/tools/r31-negative-controls
CREANCE_REPO=$HOME/r31-wt ONLY="NC-ZMINT NC-ZMINT2 NC-VISfnptr" python3 run.py   # 用例见 cases.py
```

期望：每个用例至少一项测试或 clippy 红。实际（fmt+cargo test --workspace --locked+clippy -D warnings；裁判双跑，见 logs/ 与 logs-ref/；md5 还原 OK）：

| 用例 | 注入 | 测试 | 后果 |
|---|---|---|---|
| NC-ZMINT | vm.rs 新增 `forge()`：`unsafe { std::mem::zeroed() }`；body `egress_verdict(&out).or_else(\|e\| vm::forge(profile).ok_or(e))`（temp_dir 外才铸） | 绿×2 | 生产 profile 下 verdict 失败也写 marker |
| NC-ZMINT2 | qemu/image.rs 新增 `NonNull::<EgressVerified>::dangling().as_ptr().read()`，同上 or_else | 绿×2 | 同上；image.rs 不在扫描表 |
| NC-VISfnptr | gateprobe.rs 新增 `pub(crate) const VERDICT … = egress_verdict;`，vm.rs `VERDICT(canned).ok()`，同上 or_else | 绿×2 | 零 unsafe 铸令牌（安全代码通道） |

## 建议

扫描改为 walk 全部 `src/**/*.rs`（复用已有递归 walk）而非硬编码表；ban 清单扩到 `zeroed`/`MaybeUninit`/`ptr::read`/`.read()`/`unsafe`；令牌唯一产出点改由类型系统保证（例如 egress_verdict 移入独立私有子模块，只有该模块能命名构造器），或钉 `egress_verdict` 在整个 crate 中仅出现于定义与单一调用点（禁作为值被引用）。
