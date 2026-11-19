b1-socks5-probe — R4：SOCKS5 握手违反矩阵（B1/B2 残余）。对 crates/creance-net
的真实 egress 客户端投喂恶意服务器应答：错版本/未提供方法/分片/秒断/CONNECT
变体/auth 应答版本字节/CRLF 目标注入/HTTP 204。每个变体独立 TcpListener +
线程，断言期望的拒绝（fail-closed）或记录宽容点。用法：cargo run --release
