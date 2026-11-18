# creance 攻击面地图

审查员按条目推进；状态：`未覆盖` / `进行中` / `已覆盖` / `已穷尽 N 变体`。

## A. 解析器（最高优先级：无信任输入的纯函数面）

| # | 条目 | 入口 | 状态 |
|---|---|---|---|
| A1 | 订阅 YAML 炸弹：深嵌套、锚点/别名循环、万级节点、混合类型 | creance-proxy/src/import.rs `parse_nodes` | 未覆盖 |
| A2 | 键名变体全矩阵：大小写×下划线×重复（Name/NAME/n_a_m_e…），含与 ws-opts/hysteria2 别名组合 | import.rs `normalize_import_keys` | 未覆盖 |
| A3 | dialer-proxy 环：自环/长链/跨源引用/DIRECT/分组名 | import.rs 依赖 DFS + store.rs `route` | 未覆盖 |
| A4 | hysteria2 端口/pin 规范化：畸形范围、超大端口、hex 变体、冲突组合 | import.rs `hysteria2_ports/pin` | 未覆盖 |
| A5 | config.json 畸形：64KiB 边界、未知字段、null/数字/数组换位、超长时区 | creance-vm/src/config.rs `load/validate` | 未覆盖 |
| A6 | DNS wire：压缩指针环/越界、0 长度标签、>63 标签、qdcount/ancount 不符 | creance-net/src/dnsmsg.rs `unpack` | 未覆盖 |
| A7 | HTTP 头解析：双 Content-Length、负数、非 ASCII、终结符在 8KiB 边界 | creance-net/src/wire.rs `read_header_block` | 未覆盖 |
| A8 | chunked 编码：超大 chunk 行、非法 hex、最后块后拖尾 | egress.rs `read_chunked` | 未覆盖 |

## B. egress vs 恶意代理（用 tools/ 假服务器）

| # | 条目 | 入口 | 状态 |
|---|---|---|---|
| B1 | SOCKS5 握手违反：错版本、方法循环、分片送字节、成功后立刻 RST | egress.rs `socks5_connect` | 未覆盖 |
| B2 | CONNECT 应答：非 200 状态体、畸形状态行、慢速头（deadline 行为） | egress.rs `http_connect` | 未覆盖 |
| B3 | 响应体欺骗：声明 CL 却少发/多发、EOF 中途断、Content-Length 溢出 u64 | egress.rs `read_body` | 未覆盖 |
| B4 | 重定向：11 跳、scheme 切换、userinfo 注入、八进制/十进制 IP 变体 | creance-proxy/src/fetch.rs | 未覆盖 |
| B5 | DoH 应答：id 匹配但垃圾体、rcode 变体、TTL 0、CNAME 深链 | egress.rs `exchange_dns_once` | 未覆盖 |
| B6 | deadline 语义：代理在边界时刻才响应、TLS 握手挂起 | egress.rs `dial_deadline/set_deadline` | 未覆盖 |

## C. 状态与一致性

| # | 条目 | 入口 | 状态 |
|---|---|---|---|
| C1 | store 并发写：两进程同时 import/save（原子性） | creance-proxy/src/store.rs | 未覆盖 |
| C2 | applied 一致性矩阵：revision/endpoint/selected/chain 全组合枚举 | store.rs `applied/route` | 未覆盖 |
| C3 | gate 状态机：并发 control 命令、租期到期瞬间 grant、close 后 renew | creance-gate/src/gate.rs | 未覆盖 |
| C4 | gate 鉴权：token 时序、错 Host/Origin 组合、超大 body、chunked | gate.rs `handle` | 未覆盖 |
| C5 | sync_proxy_revision：构造"恰好可采纳"的边界变更组合 | gate.rs | 未覆盖 |
| C6 | running 记录：PID 复用模拟、启动时间戳伪造 | creance-vm/src/running.rs | 未覆盖 |
| C7 | fingerprint 稳定性：归一化等价但字节不同的配置 | config.rs `fingerprint` | 未覆盖 |

## D. 路径与编排

| # | 条目 | 入口 | 状态 |
|---|---|---|---|
| D1 | 实例名注入：workspace 含 `../`、空格、unicode、512 字节 | creance-vm/src/vmname.rs + vm.rs | 未覆盖 |
| D2 | lima_home 符号链接：预占 /tmp/cage-lima-* 指向敏感目录 | vm.rs `lima_home` | 未覆盖 |
| D3 | environment_dir 伪造：environment.json/workbench.json 恶意值 | vm.rs | 未覆盖 |
| D4 | state 标记文件名碰撞：vm 名 == "base" 等保留名 | creance-vm/src/state.rs | 未覆盖 |
| D5 | export_policy 数值边界：/0、/33、255.255.255.255/0 | exit_policy.rs `masked` + 网段库 | 未覆盖 |

## E. 逃逸与探针本身

| # | 条目 | 入口 | 状态 |
|---|---|---|---|
| E1 | mounts-workspace-only 骗术：lima.yaml 注入额外挂载后探针能否发现 | creance/src/escape.rs | 未覆盖 |
| E2 | guest_script oracle：PATH 劫持 sh、只读 flag、宿主 flag 在挂载内 | escape.rs `guest_script` | 未覆盖 |
| E3 | workbench CSRF/权限：Origin 大小写、端口直觉、GET 触发变更 | creance/src/serve.rs | 未覆盖 |
| E4 | 环境剥离完整性：vm.rs STRIPPED 清单 vs Go main.go:537 清单 diff | vm.rs `sanitized_env` | 未覆盖 |

## F. 资源与健壮性

| # | 条目 | 入口 | 状态 |
|---|---|---|---|
| F1 | FD/内存：反复 dial 不 drop、超大 MAX_HEADER 攻击、gate 多实例残留 | 全局 | 未覆盖 |
| F2 | 慢速 DoS：半开连接占满 serve 64 槽位后的行为 | serve.rs | 未覆盖 |
| F3 | mihomo 控制通道：假 core.sock、慢应答、>1MiB 应答 | creance-proxy/src/service.rs `api` | 未覆盖 |

## G. 与 Go 原版语义对照（只读 /Users/shenyiyu/Documents/zcode/claude-cage-ref）

| # | 条目 | 状态 |
|---|---|---|
| G1 | egress.go vs egress.rs 逐分支 diff（错误文案、时序） | 未覆盖 |
| G2 | import.go vs import.rs 拒绝矩阵逐条 | 未覆盖 |
| G3 | gate*.go vs gate.rs 状态迁移与租期 | 未覆盖 |
| G4 | store.go vs store.rs Route/Import 语义 | 未覆盖 |

> 状态由审查员更新（本文件是 harness 中唯一允许审查员写的非 findings 文件）。
