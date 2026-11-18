# creance 攻击面地图

审查员按条目推进；状态：`未覆盖` / `进行中` / `已覆盖` / `已穷尽 N 变体`。

## A. 解析器（最高优先级：无信任输入的纯函数面）

| # | 条目 | 入口 | 状态 |
|---|---|---|---|
| A1 | 订阅 YAML 炸弹：深嵌套、锚点/别名循环、万级节点、混合类型 | creance-proxy/src/import.rs `parse_nodes` | 进行中（已穷尽 11 变体：深嵌套 O(n²)→FINDING-001 S3；超 u64 整数拒整文档→FINDING-002 S4；别名链式/自引用/前向/未定义均早停不可利用；节点数 3000/3001 与 8MiB 边界正确；inf/nan 干净拒绝；8MiB 单大标量线性 0.06s） |
| A2 | 键名变体全矩阵：大小写×下划线×重复（Name/NAME/n_a_m_e…），含与 ws-opts/hysteria2 别名组合 | import.rs `normalize_import_keys` | 已穷尽 9 变体无发现：大小写/下划线/Kelvin-U+212A 折叠/重复写法拒绝均与 Go 一致；ws-opts 大写绕过系 Go 共同语义（非漂移）；100k 键 0.16s 线性 |
| A3 | dialer-proxy 环：自环/长链/跨源引用/DIRECT/分组名 | import.rs 依赖 DFS + store.rs `route` | 已穷尽 7 变体无发现：DIRECT/分组名/自环/引用被跳过节点/下划线变体环/跨源全部正确拒绝；3000 节点深链 0.06s 通过（8MiB 主线程；2MiB workbench 线程未测，潜在栈深候选留 E3 时验证） |
| A4 | hysteria2 端口/pin 规范化：畸形范围、超大端口、hex 变体、冲突组合 | import.rs `hysteria2_ports/pin` | 已穷尽 30 变体：数字 mport 拒绝 vs Go case int 接受→FINDING-003 S4；纯 ports 字段无校验（0-1000/-443/[1,2]/反向范围原样进 store）系 Go 共同语义（上游共同缺陷，垃圾值令 mihomo 拒载 config，低危）；pin 大小写/冒号/31B/非 hex/冲突全部正确 |
| A5 | config.json 畸形：64KiB 边界、未知字段、null/数字/数组换位、超长时区 | creance-vm/src/config.rs `load/validate` | 已穷尽 22 变体：64KiB 三态/类型换位/未知字段/超长 tz/locale-lang 边界全部正确；三处 Go 漂移→FINDING-004 S5（tz 目录名 Etc、IPv6 括号代理、URL 尾斜杠） |
| A6 | DNS wire：压缩指针环/越界、0 长度标签、>63 标签、qdcount/ancount 不符 | creance-net/src/dnsmsg.rs `unpack` | 已穷尽 11 变体：指针环/自指/指 header、qd=65535、rdlen 越界、an=65535 全部正确拒绝；0x40/0x80 保留前缀标签（>63）被接受→FINDING-005 S5；pack rdlen as u16 截断地雷（不可达） |
| A7 | HTTP 头解析：双 Content-Length、负数、非 ASCII、终结符在 8KiB 边界 | creance-net/src/wire.rs `read_header_block` | 已穷尽 8 变体：16KiB 边界/非 UTF8/半截头/慢速头全部测；双 CL+垃圾 CL+半截头宽容→FINDING-006 S4；wire.rs 本身 max/EOF/leftover 语义正确 |
| A8 | chunked 编码：超大 chunk 行、非法 hex、最后块后拖尾 | egress.rs `read_chunked` | 已穷尽 7 变体：17B 行/超限/负 size/中途 EOF 正确拒绝；行边界 EOF+CRLF 畸形重同步宽容→FINDING-006 S4 |

## B. egress vs 恶意代理（用 tools/ 假服务器）

| # | 条目 | 入口 | 状态 |
|---|---|---|---|
| B1 | SOCKS5 握手违反：错版本、方法循环、分片送字节、成功后立刻 RST | egress.rs `socks5_connect` | 未覆盖 |
| B2 | CONNECT 应答：非 200 状态体、畸形状态行、慢速头（deadline 行为） | egress.rs `http_connect` | 进行中（慢速头/无 CL 挂起 deadline 正确 EAGAIN；状态行畸形拒绝 ✓；request_bounded 错误文案透传 os error 35 记 FINDING-006 附注；CONNECT 非 200 状态体与 userinfo 注入并入 B4 fetch 侧待测） |
| B3 | 响应体欺骗：声明 CL 却少发/多发、EOF 中途断、Content-Length 溢出 u64 | egress.rs `read_body` | 已穷尽 7 变体：短发/超上限/溢出 u64 正确拒绝；垃圾 CL 落 EOF 分支宽容→FINDING-006 S4；max_body+1 界全部有效 |
| B4 | 重定向：11 跳、scheme 切换、userinfo 注入、八进制/十进制 IP 变体 | creance-proxy/src/fetch.rs | 已穷尽 12 变体：mapped IPv6 绕过→FINDING-007 S2；https 策略全缺（明文订阅/userinfo/跳数 5 vs 2）→FINDING-009 S2；十进制等 IP 变体被 WHATWG 规范化挡住非问题；zone-id/join 拒绝；fragment/userinfo-redirect 案例构造受限（302 相对路径循环） |
| B5 | DoH 应答：id 匹配但垃圾体、rcode 变体、TTL 0、CNAME 深链 | egress.rs `exchange_dns_once` | 未覆盖 |
| B6 | deadline 语义：代理在边界时刻才响应、TLS 握手挂起 | egress.rs `dial_deadline/set_deadline` | 未覆盖 |

## C. 状态与一致性

| # | 条目 | 入口 | 状态 |
|---|---|---|---|
| C1 | store 并发写：两进程同时 import/save（原子性） | creance-proxy/src/store.rs | 已穷尽：**FINDING-014 S4** 丢失更新+非原子 select 实测；write_private 单写原子 ✓；三个入口（CLI/workbench/refresh）均无互斥 |
| C2 | applied 一致性矩阵：revision/endpoint/selected/chain 全组合枚举 | store.rs `applied/route` | 未覆盖 |
| C3 | gate 状态机：并发 control 命令、租期到期瞬间 grant、close 后 renew | creance-gate/src/gate.rs | 进行中（Mutex+watchdog 竞态审查干净；grant 无 Checking 前置 vs Go CheckID 绑定→FINDING-008 S4；close 后 renew 正确拒绝；并发黑盒待测——gate crate 依赖三兄弟无法独立构建，受限于源码审查） |
| C4 | gate 鉴权：token 时序、错 Host/Origin 组合、超大 body、chunked | gate.rs `handle` | 进行中（Host!=cage/Origin 存在/错 token 全 403 ✓；body 64KiB 上限+parse 失败落 0 ✓；bearer 非恒时比较 vs Go ConstantTimeCompare→FINDING-008；双 CL 后值覆盖 S5 记录；chunked body 未测——handle 不解析 TE，read_exact(CL) 恒等） |
| C5 | sync_proxy_revision：构造"恰好可采纳"的边界变更组合 | gate.rs | 未覆盖 |
| C6 | running 记录：PID 复用模拟、启动时间戳伪造 | creance-vm/src/running.rs | 已穷尽：kinfo_proc 断言验证正确（proc.h:91-98 union 重叠 p_starttime）；start token 机制健全；伪造 record（pid=1 真实 token）可致 config 变更永久受阻——同 uid 自伤面 S4 记档未单列；C2 applied 矩阵 15 变体全部正确 |
| C7 | fingerprint 稳定性：归一化等价但字节不同的配置 | config.rs `fingerprint` | 未覆盖 |

## D. 路径与编排

| # | 条目 | 入口 | 状态 |
|---|---|---|---|
| D1 | 实例名注入：workspace 含 `../`、空格、unicode、512 字节 | creance-vm/src/vmname.rs + vm.rs | 已穷尽（审查）：非字母数字折叠单 `-`+路径 hash 后缀；fit 的 char_boundary/never-empty 正确；控制字符在 abs_dir 拒绝；"base" 保留名碰撞不可能（hash 后缀恒在） |
| D2 | lima_home 符号链接：预占 /tmp/cage-lima-* 指向敏感目录 | vm.rs `lima_home` | 已穷尽 5 场景：**FINDING-010 S2**——limactl() 自删 LIMA_HOME，VM 操作全落全局 ~/.lima（profile 隔离失效、探针脱节）；link 预占不校验目标（read_link 即采用），当前被 #1 意外屏蔽、修 #1 时必须同修 |
| D3 | environment_dir 伪造：environment.json/workbench.json 恶意值 | vm.rs | 已穷尽（审查）：directory 需绝对路径+文件写权限=同 uid；影响 instance_name/gate_dir/探针路径（hash 名兜底）——自伤面记档；workbench.json 分支要求 lima.yaml 存在 |
| D4 | state 标记文件名碰撞：vm 名 == "base" 等保留名 | creance-vm/src/state.rs | 已穷尽（审查）：instance_name 恒带 hash 后缀 ≠ "base"；vmname 折叠使名字不可能含 "."→标记文件（.agent-vm-base-*）碰撞不可能 |
| D5 | export_policy 数值边界：/0、/33、255.255.255.255/0 | exit_policy.rs `masked` + 网段库 | 已穷尽：bits<8 fail-closed（整库拒绝）；data 文件 bits≤32 实测；masked 对 bits>32 移位 panic 地雷不可达（data 编译期固定）；用户面无 CIDR 输入（ip 只收单 IP） |

## E. 逃逸与探针本身

| # | 条目 | 入口 | 状态 |
|---|---|---|---|
| E1 | mounts-workspace-only 骗术：lima.yaml 注入额外挂载后探针能否发现 | creance/src/escape.rs | 进行中：**计数骗术 3 变体成立**（`-  location:` 双空格/flow 形式/折行——YAML 合法但 starts_with("- location:") 不命中）；且 FINDING-010 使探针读的 lima.yaml 与真实实例脱节；sock-abstract 探针硬编码 PASS（违背 NotEnforced 哲学）——合并待写 finding |
| E2 | guest_script oracle：PATH 劫持 sh、只读 flag、宿主 flag 在挂载内 | escape.rs `guest_script` | 进行中：env/grep/ls 为外部命令可被 guest 内 PATH 污染欺骗（hostagent 的 sanitized_env 不过滤 PATH）；`_API_KEY=` grep 比 STRIPPED 宽——宿主设 OPENAI_API_KEY 等会**误报 ESCAPE**（清单为共同窄设计，探针质量缺陷）；flag_path 注入面取决于 CLI 调用（未查） |
| E3 | workbench CSRF/权限：Origin 大小写、端口直觉、GET 触发变更 | creance/src/serve.rs | 未覆盖 |
| E4 | 环境剥离完整性：vm.rs STRIPPED 清单 vs Go main.go:537 清单 diff | vm.rs `sanitized_env` | 已穷尽：Rust=Go 12 项+5 个 cage 自有传递变量（多剥更保守）；但那 5 个含 LIMA_HOME 在 limactl 路径自删→FINDING-010；非 Anthropic *_API_KEY 两边共同不剥（探针误报项） |

## F. 资源与健壮性

| # | 条目 | 入口 | 状态 |
|---|---|---|---|
| F1 | FD/内存：反复 dial 不 drop、超大 MAX_HEADER 攻击、gate 多实例残留 | 全局 | 进行中（审查）：gate accept loop 每连接 spawn 无上限（serve.rs 有 64 上限、gate 无）——同 uid 自伤面记档；MAX_HEADER/1MiB api/take 界均正确 |
| F2 | 慢速 DoS：半开连接占满 serve 64 槽位后的行为 | serve.rs | 已穷尽（审查）：loopback-only+本机可信进程架构下自伤面；64 槽 TOCTOU 轻微超限一次性；chunked 检测对 "Transfer-Encoding:chunked"（无空格）绕过但无后续危害（S5 记档）；CSRF Origin 精确匹配/GET 只读/1MiB body 上限全部正确 |
| F3 | mihomo 控制通道：假 core.sock、慢应答、>1MiB 应答 | creance-proxy/src/service.rs `api` | 未覆盖 |

## G. 与 Go 原版语义对照（只读 /Users/shenyiyu/Documents/zcode/claude-cage-ref）

| # | 条目 | 状态 |
|---|---|---|
| G1 | egress.go vs egress.rs 逐分支 diff（错误文案、时序） | 已穷尽：socks5/CONNECT/TLS/DNS/deadline 分支已对照；已知差异集合=F-006（响应宽容 5 类）、F-013（凭据截断）、F-004（URL 校验 3 处）；no-fallback 文案一致 |
| G2 | import.go vs import.rs 拒绝矩阵逐条 | 已穷尽：拒绝矩阵/optionKey/ssh/hysteria2/wsHeaders/unsafeOption 逐行一致；差异=F-002/003（数字）+F-012（非字符串键）|
| G3 | gate*.go vs gate.rs 状态迁移与租期 | 已穷尽：Grant 五重判定（Checking/epoch/CheckID/时间戳/Authorizes 签名）vs Rust 单查 authorizes → F-008；lease 90s 值一致；fault 条件一致；Rust 缺 report.RunID/Configuration 绑定 |
| G4 | store.go vs store.rs Route/Import 语义 | 进行中：route() 的 chain/环/缺失判定一致（C2 矩阵 15 变体全对）；Import 的 refresh 保留语义有 repo 测试；Go store.go 细节未逐行 |

> 状态由审查员更新（本文件是 harness 中唯一允许审查员写的非 findings 文件）。
