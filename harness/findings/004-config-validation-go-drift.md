# FINDING-004: config.json 校验与 Go 版三处语义漂移（时区目录名 / IPv6 代理端点 / URL 尾斜杠）

- **编号**: 004
- **严重度**: S5（与 Go 原版语义漂移；均不直接破坏隔离契约）
- **攻击面**: A5（config.json 畸形）
- **发现时间**: 2026-11-18T16:20:00Z
- **发现者会话**: s01
- **状态**: 待修复

## 复现（必须）

载体：`CREANCE_CONFIG=<file> target/release/creance proxy-status`（config 校验失败即报错退出）。

| # | config 值 | Rust 实际 | Go 期望（源码推断） |
|---|---|---|---|
| 1 | `"timezone": "Etc"`（zoneinfo **目录**名） | **通过**（endpoint 正常输出） | 拒绝：`time.LoadLocation("Etc")` 打开目录读内容失败（internal/cage/config.go:88） |
| 2 | `"proxy_url": "socks5://[::1]:1080"`（IPv6 括号形式） | **拒绝** "proxy endpoint must be a numeric IP address" | 接受：`url.Parse` 的 `Hostname()` 剥掉 `[ ]` → `net.ParseIP("::1")` 成功（config.go:65-72） |
| 3 | `"proxy_url": "socks5://1.2.3.4:1080/"`（尾斜杠） | **通过**（`u.path() == "/"` 被豁免，egress.rs:48） | 拒绝：Go 要求 `u.Path == ""`（config.go:77），`/` 也是 Path |

- **期望**: 与 Go 原版一致的接受/拒绝矩阵。
- **实际**: 如上表（黑盒实测，见 attack-surfaces A5）。

## 根因猜测

1. `crates/creance-vm/src/config.rs:140-143`：用 `Path::exists()` 判定时区——目录名也 exists。Go 用 `time.LoadLocation`（要读文件内容）。连带：在**无 /usr/share/zoneinfo** 的系统上 Rust 回退为纯结构检查（两段字母数字），虚构时区 `Foo/Bar` 也会通过（macOS 上测不到，部署环境相关）。
2. `crates/creance-net/src/egress.rs:35-38`：`url::Url::host_str()` 返回带括号的 `"[::1]"`，`parse::<IpAddr>()` 失败；Go 的 `u.Hostname()` 语义是剥括号。
3. `crates/creance-net/src/egress.rs:48`：`u.path().is_empty() || u.path() == "/"` 多豁免了 `/`；Go 只有 `u.Path != ""`。

## 未验证想法

- Go 实际运行行为（本机无 go 工具链；结论来自 config.go 源码逐行阅读，置信度高）。
- `timezone: "Etc"` 会传给 lima setup 作为 guest 时区——guest 侧失败的具体形态未测（需 VM）。
- Rust `is_language_tag` 与 Go 正则同样**不限段数**（`zh-aaaa-…` 可重复至 64KiB 上限）——共同语义，未单独立项。

## 建议修复方向（供第二天的人参考，非结论）

1. 时区：优先尝试系统 zoneinfo 读取并校验是**文件**（`metadata().is_file()`），或对齐 Go 引入 tz 数据库 crate（如 `tz-rs`）做真名验证。
2. IPv6：`u.host_str()` 先剥 `[ ]` 再 parse，或改用 `url::Url::host()` 的 `Host::Ipv6` 分支。
3. 尾斜杠：去掉 `|| u.path() == "/"` 豁免（注意核对现有 config 是否有依赖此豁免的历史 profile——Go 侧无此豁免，推测历史 profile 不受影响）。
