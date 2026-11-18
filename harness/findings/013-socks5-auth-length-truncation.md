# FINDING-013: SOCKS5 认证的 user/pass 长度 `as u8` 静默截断 — 300 字节 username 发出 ULEN=44 协议破坏帧；target 有 ≤255 校验而凭据没有

- **编号**: 013
- **严重度**: S4（正确性：对合法超长凭据发出协议破坏帧，错误文案误导；Go 版报错）
- **攻击面**: B1（SOCKS5 握手）
- **发现时间**: 2026-11-19T02:30:00Z
- **发现者会话**: s01
- **状态**: 待修复

## 复现（必须）

探针：`harness/tools/a7-response-probe/src/bin/b1-socks5.rs`（恶意 SOCKS5 服务器捕获 sub-negotiation 字节）。

```sh
cd harness/tools/a7-response-probe && cargo run --release --bin b1-socks5
# [B1-CAPTURE] sub-negotiation 304 bytes: ULEN=44 (user 实际 300 字节)
```

300 个 `u` 的 username 经 `egress.rs:300` `user.len() as u8` 截断为 44（300 & 0xFF），后面只跟 44 字节用户名+错位的密码帧——服务器端解析完全错乱。

- **期望**: RFC 1929 ULEN/PLEN 上限 255；Go 版（x/net/internal/socks，egress.go:100 `proxy.SOCKS5`）对超长 username/password 返回错误。同时 `push_socks5_target`（egress.rs:523）对 host 已有 `bytes.len() > 255 → Err` 校验——**同一函数族里 target 检查了、凭据没检查**。
- **实际**: 静默截断，服务器收到畸形帧；用户看到"连接指定 SOCKS5 代理失败（failed to fill whole buffer）"——文案与真实原因（凭据过长）无关。

## 根因猜测

`crates/creance-net/src/egress.rs:300-303`：
```rust
let mut req = vec![0x01u8, user.len() as u8];
req.extend_from_slice(user.as_bytes());
req.push(pass.len() as u8);
```
与 `validate_proxy_url`（config 校验）也无关——config 允许任意长 userinfo， SOCKS5 路径在发送时才截断。HTTP CONNECT 路径（Basic 头）不受影响（无 255 限制）。

## 未验证想法

- Go x/net/internal/socks 的确切报错文案（本机无 go；依据该库源码的 `UsernameLen` 校验惯例，置信度高）。
- pass 同样截断（`pass.len() as u8`）——未单独捕获但同一代码路径。
- 真实 mihomo 作为 socks5 服务器收到 ULEN=44+错位帧的行为（失败但可能产生混淆日志）。

## 建议修复方向（供第二天的人参考，非结论）

在 `socks5_connect` 的 auth 分支加与 `push_socks5_target` 同款的长度校验：`user.len() > 255 || pass.len() > 255 → Err("SOCKS5 凭据过长（上限 255 字节）")`。或在 `validate_proxy_url` 提前拒绝（注意 http 代理的 Basic 凭据无此限制，校验应只挂 SOCKS5 路径）。

## B1 矩阵其余结论（本会话）

- 错版本/1 字节 EOF/认证失败 → 全部正确拒绝，文案携带"请求不会改为直连"契约 ✓。
- 成功应答后立即 RST → dial 返回 OK（TCP 语义，后续读写暴露）——非缺陷。
- 分片慢送 → read_exact + deadline 等待 ✓（与 B6 时序面一致）。
