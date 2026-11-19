# FINDING-022: 0.4 guest 身份声明与实现的三处差距 — username 字段未接线（guest 实际身份=宿主用户名镜像，宿主真实用户名进 guest）；load_or_create 读失败即重置身份（违背自身 never-overwrites 注释）；credentials-are-session-only 探针只 validate 单文件（profile 目录里 store.auth/gate token 同形状秘密未扫，假 PASS）

- **编号**: 022
- **严重度**: S4（①身份面：宿主用户名=潜在真实身份线索进 guest，与 "escaped, but nothing to steal" 的身份生成声明直接冲突；②③探针/健壮性缺陷）
- **攻击面**: R3 → 0.4 guestprofile（2df07a6）+ E1/E2 探针族
- **发现时间**: 2026-11-19T07:00:00Z
- **发现者会话**: r3-s01
- **状态**: 待修复

## 复现（必须）

### ① username 未接线 + 宿主身份镜像（实测）

```sh
grep -n "username" crates/creance-vm/src/lima.rs        # 无任何使用点
grep -n "useradd\|user:" crates/creance-vm/src/lima.rs  # 无用户创建
# generate_lima_yaml 无 user:/groups: 字段 → lima 默认创建宿主同名用户
creance shell -- id
# uid=501(shenyiyu) …  ← 宿主用户名直接成为 guest 用户名（实测 /tmp/p1 实例）
# tunnel.rs vsock_user() 同样：std::env::var("USER") → ssh User=<宿主用户名>
```

`Profile.username`（"dev"+8hex，含 RESERVED 校验）被生成、校验、持久化，但 **provision 从不创建该用户**——0.4 CHANGELOG 声明 "non-reserved username" 的生成身份只落地了 hostname（hostnamectl set-hostname ✓）。宿主用户名（真实姓名拼音/公司账号常见）进 guest env（USER/whoami）、ssh User 参数与日志。

### ② load_or_create 读失败即重置身份

```rust
// guestprofile.rs:75
if let Ok(bytes) = std::fs::read(&path) { … return Ok(p) }
let fresh = Profile::generate();  // read Err（权限损坏/瞬时错误）→ 走这里
crate::write_private_atomic(&path, …)  // rename 覆盖旧文件（目录可写即可）
```

注释自述 "never overwrites — a failed install keeps its identity"，但 `read` 失败（文件存在但不可读）与文件不存在不可区分 → **身份被静默重置**。并发 `load_or_create`（双进程同时未见文件）→ 双生成 → rename 后者胜 → **两个持有者令牌分叉**。

### ③ credentials-are-session-only 探针假 PASS

escape.rs 新探针：guest-profile.json 存在 → `load_or_create().is_ok()` → Contained。**声明**是 "the ONLY token shaped like a secret in the profile directory"——实现既不扫描 profile 目录（store 的 48-hex auth、gate record 的 48-hex token、proxy sources 的节点凭据都在同目录且同形状），也不检查 guest 实际 env——它只 validate 了单个 JSON 文件的格式。任何宿主凭据泄漏进 guest env 时该探针恒绿（env-credentials 探针查的是 API_KEY 形状，非 hex-token 形状）。

## 根因猜测

1. lima.rs generate_lima_yaml 未消费 `options.guest.username`——字段生成/校验链完整但最后一步（lima user: 块/useradd provision）缺失；tunnel.rs 的 `vsock_user()` 也依赖宿主 USER 而非 guest.username（ssh 用户必须是 lima 真实创建的用户——接线时两处一起改）。
2. `if let Ok` 把 IO 错误折叠为"不存在"——需要区分 NotFound 与其它错误（`matches!(e.kind(), ErrorKind::NotFound)`）。
3. 探针实现与声明脱节（F-011/016 同族：探针质量靠声明与实现对齐维护）。

## 未验证想法

- username 接线后 tunnel.rs 的 ssh User 参数、provision 的 sudo 组归属（配合 F-020 的 sudo:false）需要一起设计——三处是同一个 0.4 未完成面。
- load_or_create 并发分叉的实际触发方（setup 与 workbench 是否可能并发首次生成——setup 是 CLI 独占路径，概率低）。

## 建议修复方向（供第二天的人参考，非结论）

①lima.yaml 加 `user: {name: <profile.username>, sudo: false}`（与 F-020 联动）+ tunnel.rs 改用 profile.username；②`read` 的 NotFound 之外的错误走 Err 分支（"客机配置不可读，拒绝重置"）；③探针改为：扫描 profile 目录全部 48-hex 形状值，凡不在 guest-profile.json/store 期望集合的 → Escaped；guest env 经 ssh 抽样检查 CREANCE_SESSION_TOKEN 之外的 token 形状。
