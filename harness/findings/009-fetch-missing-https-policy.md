# FINDING-009: fetch.rs 缺失 Go 版订阅 URL 的全部 https 策略 — 明文 http 订阅被接受（订阅内容含节点凭据、明文流经 cage 出口）、userinfo 初始 URL 被接受、重定向跳数 5 vs Go 2

- **编号**: 009
- **严重度**: S2（凭据保护策略缺失：出口节点可窃听明文订阅内的节点凭据；Go 版全部拒绝）
- **攻击面**: B4（重定向/订阅获取策略）
- **发现时间**: 2026-11-19T01:00:00Z
- **发现者会话**: s01
- **状态**: 待修复

## 复现（必须）

探针：`harness/tools/a7-response-probe/src/bin/b4b-fetch-policy.rs`（fetch.rs 循环逐行拷贝 + 本地链式重定向服务器；URL 用 `localhost` hostname 使 SSRF 守卫不拦截）。

```sh
cd harness/tools/a7-response-probe && cargo run --release --bin b4b-fetch-policy
# [RUST-OK  ] init-plaintext-http body=4B    ← 初始 http:// 明文订阅被接受
# [RUST-REJ ] redirect-stays-http :: … exceeded 5 redirects   ← http→http 302 循环允许，走满 6 次请求
#            -> server 命中 6 次（Go 只允许 3 次请求）
# [RUST-OK  ] redirect-userinfo body=4B      ← 初始 URL 带 attacker:pw@ 被接受
```

Go 对照（`internal/managedproxy/fetch.go`）：
- `Fetch`：`u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != ""` → "订阅需要完整的 HTTPS 网址，不支持地址内用户名和密码"。
- `BootstrapClient().CheckRedirect`：`len(via) >= 3 || r.URL.Scheme != "https" || r.URL.User != nil` → "订阅重定向被拒绝"。

- **期望**（Go 语义四件套）：
  1. 初始订阅 URL 必须 https（明文禁）；
  2. 初始 URL 不得含 userinfo/fragment；
  3. 重定向目标必须 https 且不带 userinfo，第 3 次 redirect 前拒绝；
  4. 跳数 ≤2。
- **实际**（Rust `crates/creance-proxy/src/fetch.rs:16-80`）：全部缺失——初始 http/带 userinfo 均直接 GET；重定向对 scheme 无检查（http 链一路允许）；跳数 5（6 次请求）。

## 根因猜测

`fetch.rs` 是按 Go `Fetch` 的行为重写时**只实现了循环与 8MiB 上限**，CheckRedirect 回调与初始 URL 校验未移植。注意 Rust 的 `request_bounded` 对 scheme 的支持面（http/https）比 Go 的 BootstrapClient 更宽，缺的策略层没有底层兜底。

**威胁模型**：订阅 URL 来自 CLI `proxy-import --url` / workbench / refresh。出口节点（可能就是订阅作者或其上游）可见订阅响应明文——订阅文件里的**节点凭据**（password/uuid/private-key 内容）对出口即凭据泄漏。Go 用 https-only 把这类事故（用户手滑 http 订阅、被劫持的 http 重定向降级）整个挡住。

## 未验证想法

- workbench 的订阅添加入口是否另有 scheme 提示/校验（若有 UI 层校验，CLI 仍是缺口）。
- refresh 路径对已存的 http URL 每次刷新都重放明文（URL 持久在 store.url 字段）。
- `Subscription-Userinfo` 头的 usageSummary 对应物在 Rust 侧的处理（fetch.rs 未解析该头——S5 级功能缺失，未单列）。

## 建议修复方向（供第二天的人参考，非结论）

在 `fetch_subscription_through` 入口加 Go 的初始 URL 四连判定；循环里对 `next` 加 scheme==https + User==None 判定；`MAX_REDIRECTS` 从 5 降到 2（请求次数 ≤3）。错误文案沿用 Go 的两条。
