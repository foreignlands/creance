# F-049 — F-044 修复对 stamp 异常态 fail-open：stamp 缺失/不可读时 up 跳过漂移检查且探针报 NotEnforced（不计失败）——rm 一个文件即重启洗绿路径

- **严重度**：S4（与 F-044 同类：验收探针假绿/纪律绕过——host 侧单文件删除即恢复"guest 旧环境 + config 新承诺"的洗白，无 egress 影响）
- **攻击面**：night-10 F-044 修复面回归（任务书 A1 明确要求查"stamp 缺失/空/尾随空白行为"）
- **状态**：待修复
- **基线**：v0.5.4 `35a02f8`（完整 `sh scripts/ci.sh` RC=0）
- **复现**：纯 host 侧，`harness/tools/r9-regression` h2.0–h2.5（真实 `escape::host_probes` + `report`，无需 VM）

## 结论一句话

`cmd_up` 的漂移检查写成 `if let Ok(pinned) = std::fs::read_to_string(&stamp)`（main.rs:637-638）：**读失败=跳过检查=照常 `limactl start`**；同状态探针 `fingerprint-consistent` 对不存在的 stamp 报 `Outcome::NotEnforced`（escape.rs:182-183），而 `report()` 把 NotEnforced 计为**不失败**（escape.rs:459-461，exit 0"contained"）。于是 stop→`rm state/fingerprint.txt`→改时区→`creance up` 完整复活 F-044 封死的洗绿路径：guest 跑旧时区、config 声称新时区、escape-test 全绿退出。

## 探针实证（r9-regression，13/13 PASS）

```
h2.0 stamp=匹配                    → Contained            PASS
h2.1 stamp=匹配+尾随空白            → Contained（trim 语义） PASS
h2.2 guest 漂移 + stamp 在          → Escaped（诚实，up 会拒）PASS ← 修复主路径有效
h2.3 guest 漂移 + stamp 缺失        → NotEnforced          PASS ← 洞成立
h2.4 同状态 escape-test 退出码      → 0（⏭️ 不计入失败）    PASS ← 洗绿闭环成立
h2.5 stamp=空文件                  → Escaped（fail-closed）PASS ← 与缺失形态不对称
```

## 形态不对称矩阵（全查）

| stamp 形态 | cmd_up | 探针 | 方向 |
|---|---|---|---|
| 匹配（±尾随空白）| 放行 | Contained | ✓ |
| 漂移 | 拒绝 | Escaped | ✓（修复有效）|
| 空文件/纯空白 | 拒绝（trim→""≠fp）| Escaped | ✓ fail-closed |
| **缺失/非 UTF-8/目录/不可读（chmod 000）** | **跳过检查→放行** | **NotEnforced（exit 0）** | **✗ 双 fail-open** |

## 可达性（如实）

- 合规操作序列不可能出现"VM 存在而 stamp 缺失"——stamp 由 cmd_setup 在 create 成功后写（main.rs:582-586）。缺失=人为删除/磁盘错误/权限损坏。
- 注意 setup 的写戳失败只 `eprintln!` 警告且 setup 仍返回 0（main.rs:584-586）——**合法操作序列也存在 stamp 静默缺失的余态**（写戳失败后用户不知情，此时漂移检查永久失效）。
- 探针注释"only FS/gate probes may be NotEnforced"（escape.rs:510）的自家纪律被 fingerprint 探针的缺失形态违反——fresh-profile 测试盖不到它（无 VM）。
- F-044 修复的回归测试 `guest_drift_has_no_wash_path` 只盖"漂移+stamp 在"，缺失变体无测试。

## 修复方向（记录，不实现）

1. `cmd_up`：`match std::fs::read_to_string(&stamp)`——`Ok(pinned)` 比对照旧；`Err(_)` 一律拒绝并提示"指纹戳缺失，请 creance setup 重建"（VM 既存在则 setup 必然写过戳；读不到=异常态，fail-closed）。注意与 F-051（re-setup 死胡同）联动修。
2. 探针：stamp 缺失且实例存在时不应是 NotEnforced——instance_running 为真（或 lima home 有实例目录）+stamp 缺失 → `Escaped("fingerprint stamp missing")`；两者都缺才 NotEnforced（真 virgin profile）。
3. 回归：h2.3/h2.4/h2.5 直接搬进 escape.rs；setup 写戳失败应 fatal（或至少 setup 返回非零）而非警告。

## 关联

- F-044（本条是其修复的输入态覆盖缺口）、F-033/F-040（stamp 机制）、F-051（up 拒绝后 re-setup 路径不可达——修复方向 1 的提示会把用户引进死胡同）、F-050（同族形态：对账对 load 失败 fail-open）。
