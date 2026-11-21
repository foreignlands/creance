# creance 攻击面地图

审查员按条目推进；状态：`未覆盖` / `进行中` / `已覆盖` / `已穷尽 N 变体`。

## A. 解析器（最高优先级：无信任输入的纯函数面）

| # | 条目 | 入口 | 状态 |
|---|---|---|---|
| A1 | 订阅 YAML 炸弹：深嵌套、锚点/别名循环、万级节点、混合类型 | creance-proxy/src/import.rs `parse_nodes` | 已穷尽 11 变体（R8 收口）：深嵌套 O(n²)→FINDING-001 S3；超 u64 整数拒整文档→FINDING-002 S4；别名链式/自引用/前向/未定义均早停不可利用；节点数 3000/3001 与 8MiB 边界正确；inf/nan 干净拒绝；8MiB 单大标量线性 0.06s |
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
| B1 | SOCKS5 握手违反：错版本、方法循环、分片送字节、成功后立刻 RST | egress.rs `socks5_connect` | 已覆盖（R4 实测 15 变体 harness/tools/b1-socks5-probe：错版本/未提供方法/0xFF/RST/CONNECT 错版本/失败码/未知 atyp/截断/超期慢应答/EOF 全 fail-closed ✓；慢滴答在 deadline 内合法接受；auth 应答版本字节不查（E——x/net proxy 疑似同样只查 status，平价未定证，无安全影响）；**dial 目标 CRLF 注入 CONNECT 头可行（M2）但生产不可达（request_bounded 走 WHATWG 规范化、check 走常量）→ FINDING-030 S5 API 硬化**） |
| B2 | CONNECT 应答：非 200 状态体、畸形状态行、慢速头（deadline 行为） | egress.rs `http_connect` | 已覆盖（R4：204 拒绝与 Go `!= StatusOK` 逐字对齐 ✓；畸形状态行/慢速头/无 CL 此前已测；userinfo 凭据经 base64 中和 CRLF 无注入面；非 200 状态体语义并入 B4 结论） |
| B3 | 响应体欺骗：声明 CL 却少发/多发、EOF 中途断、Content-Length 溢出 u64 | egress.rs `read_body` | 已穷尽 7 变体：短发/超上限/溢出 u64 正确拒绝；垃圾 CL 落 EOF 分支宽容→FINDING-006 S4；max_body+1 界全部有效 |
| B4 | 重定向：11 跳、scheme 切换、userinfo 注入、八进制/十进制 IP 变体 | creance-proxy/src/fetch.rs | 已穷尽 12 变体：mapped IPv6 绕过→FINDING-007 S2；https 策略全缺（明文订阅/userinfo/跳数 5 vs 2）→FINDING-009 S2；十进制等 IP 变体被 WHATWG 规范化挡住非问题；zone-id/join 拒绝；fragment/userinfo-redirect 案例构造受限（302 相对路径循环） |
| B5 | DoH 应答：id 匹配但垃圾体、rcode 变体、TTL 0、CNAME 深链 | egress.rs `exchange_dns_once` | 已覆盖（R4 源码审查：429/5xx 三次有界重试+退避、其他非 200/unpack 失败/id 不匹配/非 response 全 fail-closed 不重试；question 段不比对——但投毒者需先控代理=已是全权 MITM 无新获权，设计注记非 finding；TTL/CNAME 纯透传无客户端追逐；A6 已覆盖 unpack 面垃圾） |
| B6 | deadline 语义：代理在边界时刻才响应、TLS 握手挂起 | egress.rs `dial_deadline/set_deadline` | 已覆盖（R4：deadline 在 socket 上、握手各步共享同一 deadline（dial_deadline 先 set_deadline 再 socks/http/tls）→ TLS 挂起/边界响应同超时路径；b1 工具变体 K 实证超期拒绝；J 证明 deadline 内慢滴答合法接受） |

## C. 状态与一致性

| # | 条目 | 入口 | 状态 |
|---|---|---|---|
| C1 | store 并发写：两进程同时 import/save（原子性） | creance-proxy/src/store.rs | 已穷尽：**FINDING-014 S4** 丢失更新+非原子 select 实测；write_private 单写原子 ✓；三个入口（CLI/workbench/refresh）均无互斥 |
| C2 | applied 一致性矩阵：revision/endpoint/selected/chain 全组合枚举 | store.rs `applied/route` | 已覆盖（R5：15 变体全部正确，见 C6 行尾记录） |
| C3 | gate 状态机：并发 control 命令、租期到期瞬间 grant、close 后 renew | creance-gate/src/gate.rs | 已覆盖（R4 实机黑盒：hammer 12 轮+确定性双守护——**FINDING-028 S2** 守护战争（败者永生、closed 期间 wire 间歇可用）、**FINDING-029 S4** retire_stale_record 误删活 record、**FINDING-027 S4** 僵尸 ssh 骗过 pidfile；单守护下 closed=wire down、forged renew/grant 拒绝、drain 无残留隧道全部正确；record/config 原子写核验）。**R5 night-06 修复面回归**：run_id 绑定边角（rename 原子无撕裂；`Err=>continue` 持续损坏 record → 守护永生+control 全 403 砖化+watchdog 持线不动，同 uid 自伤面记档，CLI touch 即愈）；disown×stop 并发收敛 ✓；双 up 收敛 ✓；still_owner 消失拍 → 不动 wire ✓；**spawn_daemon 去重命中垂死守护 → FINDING-035 S4**（确定性探针）；r4 对照证 F-028 disown 机制在损坏 record 重生面成立 ✓；daemon_serving 非 socket 路径 ENOTSOCK→保守当活（方向正确，自伤面记档） |
| C4 | gate 鉴权：token 时序、错 Host/Origin 组合、超大 body、chunked | gate.rs `handle` | 已覆盖（Host!=cage/Origin 存在/错 token 全 403 ✓；body 64KiB 上限+parse 失败落 0 ✓；bearer 非恒时比较→FINDING-008；双 CL 后值覆盖 S5 记录；chunked body 不解析 TE，read_exact(CL) 恒等；**R7**：token 内存化回归——record 外部改写→403 死锁无自愈（up 放行，stop 唯愈）判非 finding 被同 uid config 改写支配；grant 时间矩阵 t1-t7 全拒（r7-sync-matrix）；record 改写+TOCTOU 案见 findings/041 已排除节） |
| C5 | sync_proxy_revision：构造"恰好可采纳"的边界变更组合 | gate.rs | 已覆盖（R4 源码审查+R7 重审兑现：采纳路径=revision 变更或 exit_policy 完成+strip_config 相等+only-completed 校验+新 revision 非空，与 Go SyncProxyRevision 对齐；**R4 预警的 Unchanged 分支 exit_policy 静默忽略在 0.5 输入面下已实证成洞 → FINDING-041 S4**（r7-sync-matrix m1-m5）；幂等保护与 select 必关的语义分叉 → FINDING-043）。**R8 修复面回归（r8-regression H1，真实 Gate+GateClient 7/7）**：F-041 修复后 bound→bound 换锚 fail-closed ✓、干净幂等保持 ✓、部分绑定（仍 needs_binding）原样重写=Unchanged/填格仍欠=Err ✓（部分绑定落 branch 1）、绑定完成→Adopted ✓、等价锚 raw "us" 归一后 Unchanged ✓（load 时 normalize，无误判）、un-bind 拒绝 ✓——矩阵全 fail-closed，无新洞 |
| C6 | running 记录：PID 复用模拟、启动时间戳伪造 | creance-vm/src/running.rs | 已穷尽：kinfo_proc 断言验证正确（proc.h:91-98 union 重叠 p_starttime）；start token 机制健全；伪造 record（pid=1 真实 token）可致 config 变更永久受阻——同 uid 自伤面 S4 记档未单列；C2 applied 矩阵 15 变体全部正确 |
| C7 | fingerprint 稳定性：归一化等价但字节不同的配置 | config.rs `fingerprint` | 已穷尽（R5）：结构体序列化 sha256（字段序固定 → 文件字节序/空白无关）；exit_policy 先 normalized 再哈希 → 等价策略同指纹 ✓；proxy_revision 有意入指纹（select/refresh 即漂移，由 running.rs 拦 `up`，保守方向）。**fingerprint-consistent 探针死代码 → FINDING-033 S5**（fingerprint.txt 全仓库无写入者，恒 NotEnforced；night-07 修复激活）。**R8 承诺面盘点 → FINDING-044 S4 + FINDING-045 S5**：F-040 后戳=guest 三字段，up 刷戳把 stop→edit→up 的真实漂移洗绿（探针实证）；browser_language 承诺无供给+Go CAGE_* env 链缺失；dns_url 两版同形硬编码不进 guest（排除正确） |

## D. 路径与编排

| # | 条目 | 入口 | 状态 |
|---|---|---|---|
| D1 | 实例名注入：workspace 含 `../`、空格、unicode、512 字节 | creance-vm/src/vmname.rs + vm.rs | 已穷尽（审查）：非字母数字折叠单 `-`+路径 hash 后缀；fit 的 char_boundary/never-empty 正确；控制字符在 abs_dir 拒绝；"base" 保留名碰撞不可能（hash 后缀恒在） |
| D2 | lima_home 符号链接：预占 /tmp/vmhome-*（0.6.3 前叫 /tmp/cage-lima-*）指向敏感目录 | vm.rs `lima_home` | 已穷尽 5 场景：**FINDING-010 S2**——limactl() 自删 LIMA_HOME，VM 操作全落全局 ~/.lima（profile 隔离失效、探针脱节）；link 预占不校验目标（read_link 即采用），当前被 #1 意外屏蔽、修 #1 时必须同修。2026-11-21 冒烟观察：链接从不回收（cargo test 的 workbench 临时 profile 会在 /tmp 留下指向已删目录的死链，实测 4 条）——卫生问题非洞，记档 |
| D3 | environment_dir 伪造：environment.json/workbench.json 恶意值 | vm.rs | 已穷尽（审查）：directory 需绝对路径+文件写权限=同 uid；影响 instance_name/gate_dir/探针路径（hash 名兜底）——自伤面记档；workbench.json 分支要求 lima.yaml 存在 |
| D4 | state 标记文件名碰撞：vm 名 == "base" 等保留名 | creance-vm/src/state.rs | 已穷尽（审查）：instance_name 恒带 hash 后缀 ≠ "base"；vmname 折叠使名字不可能含 "."→标记文件（.agent-vm-base-*）碰撞不可能 |
| D5 | export_policy 数值边界：/0、/33、255.255.255.255/0 | exit_policy.rs `masked` + 网段库 | 已穷尽：bits<8 fail-closed（整库拒绝）；data 文件 bits≤32 实测；masked 对 bits>32 移位 panic 地雷不可达（data 编译期固定）；用户面无 CIDR 输入（ip 只收单 IP） |

## E. 逃逸与探针本身

| # | 条目 | 入口 | 状态 |
|---|---|---|---|
| E1 | mounts-workspace-only 骗术：lima.yaml 注入额外挂载后探针能否发现 | creance/src/escape.rs | 已覆盖（并入 FINDING-011，night-03 已修复——本行"合并待写"状态系过期标记，R5 核实：count_declared_mounts 现为真 YAML 解析+merge key fail-close（F-016），sock-abstract 现报 SKIP 不谎 PASS） |
| E2 | guest_script oracle：PATH 劫持 sh、只读 flag、宿主 flag 在挂载内 | escape.rs `guest_script` | 已覆盖（F-011/F-022 修复面 + R5 复核）：探针命令全用绝对路径（/usr/bin/id、/usr/bin/sudo）抗 PATH 污染；`_API_KEY=` grep 误报项=共同窄设计记档不变；flag 路径由 CLI 从 environment_dir 推导（D3 已覆盖伪造面）；escape-test 的宿主侧探针（credentials/mounts/fingerprint）R5 已分别回归（F-032/F-033） |
| E3 | workbench CSRF/权限：Origin 大小写、端口直觉、GET 触发变更 | creance/src/serve.rs | 已覆盖（R5 审查）：CSRF=POST 且非空 Origin 必须精确等于 `http://127.0.0.1:{bound port}`（大小写不折叠、端口绑实值）；GET 仅读（/,/api/status,/api/nodes）✓；DNS rebinding 场景 Origin=attacker 域→403；无 Origin 本地客户端=文档化信任边界（loopback+同 uid）；/api/proxy/import 的任意 url 经 fetch_subscription 继承 B4 全套守卫（SSRF 不逃逸）；/api/check 固定 URL 无参数注入；chunked 无空格绕过无危害（body 解析 400）已 F2 记档 |
| E4 | 环境剥离完整性：vm.rs STRIPPED 清单 vs Go main.go:537 清单 diff | vm.rs `sanitized_env` | 已穷尽：Rust=Go 12 项+5 个 cage 自有传递变量（多剥更保守）；但那 5 个含 LIMA_HOME 在 limactl 路径自删→FINDING-010；非 Anthropic *_API_KEY 两边共同不剥（探针误报项） |
| E5 | 探针 3（proxy-numeric-endpoint）是空探针：两 match 臂都返回 Contained | escape.rs | **已知空洞，未覆盖**（AUDIT-2026-11-21 待审 #1，裁定"实现或删除"缓做）：它在宿主强制清单里恒绿，虚增"已强制探针"计数。下轮审计应先逼出一个裁定：非数字主机名=逃逸的真校验，或删探针改计数 |

## F. 资源与健壮性

| # | 条目 | 入口 | 状态 |
|---|---|---|---|
| F1 | FD/内存：反复 dial 不 drop、超大 MAX_HEADER 攻击、gate 多实例残留 | 全局 | 已覆盖（R8 收口）：gate accept loop 每连接 spawn 无上限（serve.rs 有 64 上限、gate 无）——同 uid 自伤面记档；MAX_HEADER/1MiB api/take 界均正确 |
| F2 | 慢速 DoS：半开连接占满 serve 64 槽位后的行为 | serve.rs | 已穷尽（审查）：loopback-only+本机可信进程架构下自伤面；64 槽 TOCTOU 轻微超限一次性；chunked 检测对 "Transfer-Encoding:chunked"（无空格）绕过但无后续危害（S5 记档）；CSRF Origin 精确匹配/GET 只读/1MiB body 上限全部正确 |
| F3 | mihomo 控制通道：假 core.sock、慢应答、>1MiB 应答 | creance-proxy/src/service.rs `api` | 已覆盖（R4 审查：应答上限/读界正确；假 core.sock=同 uid 预占=自伤面，无 fail-open；慢应答受读界与预算约束。**R7 真核心在环完成（R6 未验证想法兑现）→ FINDING-042 S4**：external-controller-unix 零认证，PATCH mode=direct / SAFE_PATHS 内 yaml 重载实测成立，出口证据预言机被无痕劫持；guest 不可达；Go 同形非漂移；night-09 修复=secret 保留+gate-open 前置 check_running 对账，负对照实测 mode=direct 被拒 ✓）。**R8 残余面 → FINDING-046 S4**：对账集五字段+组选择不含 /rules（假核心在环实证盲区）——保 mode+伪装组选择的规则级重载自述穿透；TOCTOU 不独立成洞；SAFE_PATHS 同 uid 设计地板；unix 免鉴已结案（文件权限即鉴权，mihomo 设计） |

## G. 与 Go 原版语义对照（只读 Go 参考仓库 <path-to-the-Go-reference-checkout>）

| # | 条目 | 状态 |
|---|---|---|
| G1 | egress.go vs egress.rs 逐分支 diff（错误文案、时序） | 已穷尽：socks5/CONNECT/TLS/DNS/deadline 分支已对照；已知差异集合=F-006（响应宽容 5 类）、F-013（凭据截断）、F-004（URL 校验 3 处）；no-fallback 文案一致 |
| G2 | import.go vs import.rs 拒绝矩阵逐条 | 已穷尽：拒绝矩阵/optionKey/ssh/hysteria2/wsHeaders/unsafeOption 逐行一致；差异=F-002/003（数字）+F-012（非字符串键）|
| G3 | gate*.go vs gate.rs 状态迁移与租期 | 已穷尽：Grant 五重判定（Checking/epoch/CheckID/时间戳/Authorizes 签名）vs Rust 单查 authorizes → F-008；lease 90s 值一致；fault 条件一致；RunID 绑定 night-08 已落 ✓；**Configuration 绑定+Renew 重授权+24h 硬顶+预铸下界仍缺 → R7 设计审查文档 harness/go-authz-alignment.md（对齐面待重排 0.7/0.8，0.6 被 Linux 移植占用）** |
| G4 | store.go vs store.rs Route/Import 语义 | 已覆盖：route() 的 chain/环/缺失判定一致（C2 矩阵 15 变体全对）；Import 的 refresh 保留语义有 repo 测试；**R7 select 语义对照：Go applyProxy 每次 select/restart/route 同步 closeProxyGate（proxy.go:334），Rust select_and_apply 不触碰 gate → FINDING-043 S5**（night-09 两入口已同步撤 gate）。**R8 收尾抽查 → FINDING-047 S5**：close 失败分支 Go 事务性（中止+defer 回滚）vs Rust 先落地后 `let _` 吞错（窗口 ≤90s lease 有界+再 open 被 selection 对账拒）；Go validateProxyCore 在 select 前拒坏节点、Rust 延迟到 proxy-start（fail-closed UX 漂移，不立案）；route/链式切换无 Rust 缺口（workbench 无独立 route 动作，select 覆盖）；Go store.go 其余（Import 校验/unsafeOption/Runtime 生成）逐行结论与 G2/F3 一致 |

## H. Linux QEMU 后端（v0.6.0 新面，全部未覆盖——下轮夜间审计的主攻区）

条目按"guest 视角可达性"排序：guest 真正够得着的面优先于同 uid 自伤面。

| # | 条目 | 入口 | 状态 |
|---|---|---|---|
| H1 | **guest→宿主 slirp 可达面**：user 网络下 guest 可拨 10.0.2.2（=宿主回环）；`restrict=on` 未启用（runner.rs:147 注释称供给期需要），ROADMAP 挂"按启停状态启用"——隔离契约（guest 只经 ssh -R 隧道出网）在 hostfwd 之外的这条平行通路是否真的被 iptables 封死、供给完成后是否有窗口 | crates/creance-vm/src/qemu/runner.rs（netdev 参数组装）+ provision.rs（guest 侧 OUTPUT 链） | 未覆盖（**最高优先**：这是 containment 主张在 Linux 后端的直接考验；对照 macOS 侧 usernet 拒 RFC1918 的先例） |
| H2 | hostfwd 唯一性绑定：`hostfwd=tcp:127.0.0.1:{port}-:22` 端口在 setup 分配冻结进 instance.json——同 uid 预占端口/改写 instance.json 换端口的后果；wait_ssh 早退（H2 修复）后的 TOCTOU 残窗 | qemu/runner.rs + qemu/mod.rs `Instance` | 未覆盖 |
| H3 | vFAT 种子链：seed.img 由 fatfs 原地构建（CIDATA 标签）；同 uid 在 stop→up 之间改写 seed.img = 下次开机注入任意 cloud-init（供给脚本在 containment 之前以 root 跑）——写入面=实例目录权限；user-data 经 Yaml→cloud-init 双跳的引号/结构保真 | qemu/seed.rs + qemu/provision.rs | 未覆盖（对照 F-052 家族：同 uid 改文件洗绿/注入） |
| H4 | QMP 控制通道：qmp.sock 在实例目录（0700 目录内），全功能 QMP（device_add/nbd 级）对同 uid 开放=自伤面；停机梯 QMP powerdown→SIGTERM(token)→SIGKILL(token) 的 token 判定与"qemu 拒绝退出"报错的可达性 | qemu/runner.rs `qmp_powerdown`/`stop_ladder` | 未覆盖 |
| H5 | /proc starttime 令牌：stat_starttime 按"最后一个右括号"切分（comm 含括号/空格有测试）；hidepid 下 token="" 时 pidfile 守卫退化语义（空 token 恒过还是恒拒？）；PID 复用窗口在 Linux 侧的实际宽度 | creance-vm/src/pidfile.rs `process_start_token`(linux) | 未覆盖（对照 C6 的 macOS kinfo_proc 面） |
| H6 | 进程内核心监督（Linux 侧 service.rs）：relay 分离进程组+env_clear 后靠 pidfile（记的是 relay 的 pid）+控制 socket 活性双判；孤儿收割 `reap_orphan_cores` 的签名匹配（`<dir>/mihomo -d <dir>`）与 ppid==1 判定的误杀/漏杀面（2026-11-21 新代码，理应被审） | creance-proxy/src/service.rs `launch_supervised`/`stop_local`/`reap_orphan_cores` | 未覆盖 |
| H7 | 镜像供给链：ensure_base_image 从 cloud-images.ubuntu.com 拉 img+SHA256SUMS 校验——SUMS 文件本身的来源信任（同 HTTPS 通道）、部分下载残尸的原子性、release_dir 拼写的路径注入 | qemu/image.rs `ensure_base_image`/`parse_sum`/`fetch` | 未覆盖（对照 fetch-proxy-core 钉版+哈希的信任模型差异：一个信 release 附带校验和，一个信仓库自录） |

> 状态由审查员更新（本文件是 harness 中唯一允许审查员写的非 findings 文件）。

> 状态由审查员更新（本文件是 harness 中唯一允许审查员写的非 findings 文件）。
