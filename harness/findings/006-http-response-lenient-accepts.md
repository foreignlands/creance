# FINDING-006: egress 对恶意 HTTP 响应的五类宽容接受 — 截断/畸形响应被当作成功（Go 侧严格拒绝）

- **编号**: 006
- **严重度**: S4（正确性/与 Go 语义漂移；有界、不违反无直连回退契约）
- **攻击面**: A7 + A8 + B2 + B3（HTTP 头解析 / chunked / 响应体欺骗）
- **发现时间**: 2026-11-19T00:10:00Z
- **发现者会话**: s01
- **状态**: 待修复

## 复现（必须）

探针：`harness/tools/a7-response-probe/`。恶意目标服务器在 MixedProxy 的 CONNECT 隧道后发畸形响应，驱动生产 `request_bounded()` 完整链路（socks5 握手 → CONNECT → 读响应）。注意 `src/testsupport_fixed.rs` 是 `crates/creance-net/src/testsupport.rs` 的拷贝，仅修正了 `relay()` 的关闭顺序 bug（原版 `client.shutdown(Write)` 在 `up.join()` 之后——FIN 永不发出，EOF 攻击类 case 全部死锁到 deadline；**这个 harness bug 本身值得反馈给仓库**，生产 egress 不受影响）。

```sh
cd harness/tools/a7-response-probe && cargo run --release
```

五类宽容接受（全部黑盒实测 ACCEPT）：

| # | 恶意响应 | Rust 实际 | Go 语义（源码推断） |
|---|---|---|---|
| 1 | chunked，最后一个 chunk 行边界处 EOF（`…3\r\nabc\r\n` 后断开） | **ACCEPT** body="abc" | `httputil`/`net/http` chunked reader：unexpected EOF 拒绝 |
| 2 | chunk 数据后 CRLF 位置是垃圾（`3\r\nabcZZ5\r\nhello…`） | **ACCEPT** body="abchello"（"ZZ" 被静默吞作 CRLF） | CRLF 必须精确，畸形报错 |
| 3 | 双 Content-Length 不同值（`CL: 3` + `CL: 10`） | **ACCEPT** 按第一个 take(3) | 消息歧义，transport 层报错 |
| 4 | `Content-Length: abc`（垃圾值）+ body + EOF | **ACCEPT** 落入"无 CL"分支读 EOF 得 body | bad Content-Length 报错 |
| 5 | 半截头块（`HTTP/1.1 200 OK\r\nX` 后 EOF） | **ACCEPT** status=200、空 body（第一行完整即通过；无冒号行被 parse_headers 丢弃） | unexpected EOF 拒绝 |

正确拒绝的对照（同一矩阵）：chunk 数据中途 EOF / chunk 行 >16 字节 / chunk size 超上限 / 负 size / CL 短发 / CL 超上限 / 非 UTF8 头 / 头 16KiB+1 / 慢速头超 deadline / 无 CL 挂起超 deadline —— 全部 REJECT ✓。

- **期望**: 对齐 Go 的严格性——上述五类应拒绝（"incomplete HTTP response body" / "invalid chunk terminator" / "ambiguous Content-Length" / "invalid HTTP response"）。
- **实际**: 如表。

## 根因猜测

均在 `crates/creance-net/src/egress.rs`：
1. `read_chunked:782-783`：chunk 行 `read == 0 → return Ok(body)` —— 行边界 EOF 静默成功（与 CL 路径的 `body.len() != len → Err` 不一致）。
2. `read_chunked:805-806`：`let _ = channel.read_exact(&mut crlf);` —— chunk 终止 CRLF 不校验，任意 2 字节被吞并"重同步"到下一 chunk。
3. `read_body:748`：`find` 取第一个 CL；双 CL 不拒绝。
4. `read_body:748`：CL parse 失败静默落入无 CL 的 EOF 读分支（有 `max_body+1` 界，无拒绝）。
5. `wire.rs read_header_block:23-24` + `parse_status`：EOF 半截头块被当成功返回，`parse_status` 只看第一行。

**危害面**：恶意/被劫持的订阅服务器可让截断或损坏的响应被 `fetch_subscription` 当作成功数据进入 `parse_nodes`/store（首次导入少给节点、refresh 触发 route 保留检查——部分场景被 store 层兜住，但"成功"语义本身漂移）；DoH 路径有 `unpack`+id 校验兜底，风险更低。

## 未验证想法

- `request_bounded` 错误路径直接 `e.to_string()` 透传 OS 文案（"Resource temporarily unavailable (os error 35)"），未走 `user_error` 的友好超时分类——与 socks5/connect 路径文案不一致（S5 附加观察，工作台用户可见）。
- Go 实际行为未实跑（无 go 工具链；依据 net/http 与 httputil/chunked 的文档语义与惯例，置信度高）。
- chunked 大流量慢推（每个 chunk 间隔 < deadline）的累积行为——受 max_body 界，未单测。

## 建议修复方向（供第二天的人参考，非结论）

1. `read_chunked`：行边界 EOF 返回 Err（"incomplete chunked body"）；CRLF read_exact 不再 `let _ =`，校验字节 == `\r\n`。
2. `read_body`：双 CL 值不同 → Err；CL parse 失败 → Err（而非落 EOF 分支）。
3. `wire.rs`/`parse_status`：EOF 且未找到终结符 → Err（调用方 `request_bounded` 无法区分"干净读完头"与"断线半截头"）。
4. `request_bounded` 的 io 错误映射到 `user_error` 同款超时文案。
