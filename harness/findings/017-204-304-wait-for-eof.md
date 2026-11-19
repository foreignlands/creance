# FINDING-017: 204/304 无 body 响应被当作"无 Content-Length，读至 EOF"——服务器合理保持连接时 egress 挂满整个 deadline 后报错；Go net/http 按状态码立即完成；proxy-refresh 遇 304 场景稳定触发

- **编号**: 017
- **严重度**: S4（正确性/可用性：合法且常见的 304 refresh 响应挂满 60s 后失败；非 night-02 回归，R1 未覆盖的原有时序缺陷）
- **攻击面**: R2 回归审查 → night-02（5cf4613）审查引入发现；B2/B3 相邻
- **发现时间**: 2026-11-19T01:44:47Z
- **发现者会话**: r2-s01
- **状态**: 待修复

## 复现（必须）

探针：`harness/tools/a7-response-probe/src/bin/r2-204.rs`（服务器发响应头后**保持连接打开 10s**——RFC 合法行为）。

```sh
cd harness/tools/a7-response-probe && cargo run --release --bin r2-204
# [204-no-cl-hold] REJECT :: Resource temporarily unavailable (os error 35) elapsed=4.0s
# [304-no-cl-hold] REJECT :: Resource temporarily unavailable (os error 35) elapsed=4.0s
# [200-cl0-hold]   ACCEPT status=200 body=0B elapsed=0.0s   ← 对照：CL:0 立即完成
```

- **期望**: RFC 7230 §3.3.3——204/304 响应**没有消息体**，HEAD 亦然。Go `net/http` 按状态码与方法立即结束 body 读取，不等 EOF。本仓库 `fetch_subscription` 走 GET；订阅服务器对未变更的订阅返回 `304 Not Modified`（ETag/If-Modified-Since 协商，标准行为）且**不必关闭连接**——此时 `request_bounded` 应立即返回 304。
- **实际**: `read_body` 不看状态码，204/304 无 CL 落入"读 EOF"分支 → 服务器保持连接 → 读满 deadline（fetch 路径 60s）→ `"Resource temporarily unavailable (os error 35)"`（该错误文案问题见 FINDING-006 附注）→ refresh 报错。**实际触发面**：`creance proxy-refresh` 定时刷新 + 订阅服务器支持 304 协商 = 每次刷新挂 60s 且 refreshed 计数不增（CLI 退出码 2）。

## 根因猜测

`crates/creance-net/src/egress.rs` `read_body` 的 None 分支（night-02 重构后仍保持原语义）。修复方式与 Go 对齐：`request_bounded` 里拿得到 status（parse_status 已算出），把 `(status == 204 || status == 304 || method == HEAD)` 传给 `read_body` 走零体路径。night-02 的 F-006 修复只严格化了 CL/chunked，没有触及这个分支——**非回归，是 R1 漏测的原有缺陷**（R1 矩阵只测了 200 形态）。

## 未验证想法

- Go 版 egress.go 用 `http.ReadResponse` + 标准 client——204/304 自动按无体处理（源码推断，无 go 工具链未实跑）。
- 304 挂 60s 的用户可见性：refresh 是定时器/CLI 驱动，无人观察超时——但 refreshed=0 会让"订阅有更新却显示刷新失败"。
- HEAD 请求：本仓库无 HEAD 调用方（不可达，修复时可顺带覆盖）。

## 建议修复方向（供第二天的人参考，非结论）

`request_bounded` 已有 `status`：构造 `let no_body = status == 204 || status == 304;` 传入 `read_body`，no_body 时直接 `Ok(Vec::new())`（连接随后关闭）。顺带把 None 分支的 io 错误映射为 user_error 超时文案（FINDING-006 附注）。
