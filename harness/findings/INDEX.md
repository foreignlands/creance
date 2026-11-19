# Findings Index

| # | 严重度 | 标题 | 攻击面 | 状态 |
|---|---|---|---|---|
<!-- NNN | S? | 一句话 | A? | 待修复/已修复(commit)/误报 -->
| 040 | S4 | F-033 回归：setup 指纹戳覆盖全 config（含 proxy/revision/exit_policy），任何合法 select/重启使 escape-test 恒报 Escaped（探针 H4 实证前提）；record 源吸收漂移、戳源永久报警，双源冲突 | R6-B3 | 待修复 |
| 039 | S5 | 幽灵 workspace 清单 crates/Cargo.toml（git tracked，ff286a6 残尸，0.2.0/your-org）阻断外部 path-dep：继承绑定旧版+crates/crates/ 双倍路径（实测 build error） | R6-C 工具链 | 已修复（night-08：幽灵清单删除，path-dep 实证通过） |
| 038 | S4 | 出口证据=单目的地采样被泛化为全流量锚定：出口节点差异化路由可洗白大陆出口（TLS 防 MITM/核心单 MATCH/parse_trace 15 项矩阵均已验证封死，唯一开放路径在节点以外） | R6-A1 | 已修复（night-08：单目的地边界如实声明+审计 exit_sample 标注） |
| 037 | S2 | gate 认证 fail-open：record 不可读→token 退化空串，空 Bearer 过恒时比较；无凭证进程 check→grant→Open 全链成立（探针实证）；Go 用启动时内存 token 恒拒——语义漂移。边界=同 uid+close 瞬态窗口，guest 不可达 | R6-A4/A3 | 已修复（night-08：token 内存化 fail-closed，r6 探针实证全拒） |
| 036 | S4 | exit-anchor 漂移链零绑定：grant 契约 5 键字符串表 vs Go 11 项+RunID+Configuration+CreatedAt+24h+Renew 重授权；daemon 逐命令 applied() 对 co-updated revision 结构性失明；workbench start 不 sync、CLI start 先重启后 sync 且吞错——换节点后伪造五键静默再 Open（探针 H3 实证），90s 租期为唯一硬顶。C5 预埋分支复查：action 对 Ok 也无条件关 gate（静默担忧不落地），但幂等 sync 也关（注释矛盾，proxy-start 强制重取证） | R6-A2/A3 + attack-surfaces C5 | 已修复（night-08：start 先 sync+幂等不关+grant 绑 run/时间） |
| 035 | S4 | spawn_daemon 的 pidfile-alive 去重命中垂死守护（确定性探针复现）：up 返回 Ok 而终态无守护无 record；对称风险=stop 的 close_and_remove 可刺杀并发 up 的年轻 record | R5-1 F-028 修复面回归 | 已修复（night-07：等待一拍分离在途/垂死） |
| 034 | S4 | provision curl -o 失败残留半截 /usr/local/bin/node 遮蔽 apt 兜底的 /usr/bin/node（PATH 先序）→ 兜底链被尸体击败；containment 不受影响 | R5-4 F-031 修复面回归 | 已修复（night-07：tmp+mv 原子下载） |
| 033 | S5 | fingerprint-consistent 探针死代码：fingerprint.txt 全仓库无写入者，恒 NotEnforced（"layer not implemented yet"）；漂移检测实际由 running.rs 承担 | R5-6 C7 | 已修复（night-07：setup 写戳，探针激活） |
| 032 | S4 | 订阅内容恰 48-hex 字符串（password 等）经 sources.json 被 scan_unknown_tokens 判 unknown → escape-test 误报 Escaped exit 1（实测；64-hex/干净订阅对照不触发）——远程内容可操纵信任预言机 | R5-5 期望集回归 | 已修复（night-07，实机重放） |
| 031 | S4 | provision 的 set -e 使安装失败=部署 fail-open：apt/curl 失败中断脚本，拓扑锁定与特权摘除全部不执行 | R4 F-020 回归残留（night-06 核实） | 已修复（night-06） |
| 030 | S5 | Egress::dial 目标含 CRLF（尾冒号数字端口形状）可向 HTTP 代理 CONNECT 请求注入任意头部（实测成立）；生产不可达（fetch 走 WHATWG 规范化）——API 加固 | B1/B2 | 已修复（night-06） |
| 029 | S4 | retire_stale_record `!is_ok()` 把 5s 读超时当守护已死：冻结/慢守护即被 `creance up` 删活 record+切隧道+更替守护+gate 静默跌落 Closed（实机复现）；与 close_gates 的 "unreachable" 字符串判定双标 | night-05 修复面回归（C3） | 已修复（night-06，实机复验冻结 no-op） |
| 028 | S2 | 双守护战争：spawn 竞态/直接双抛 → 败者凭 record 路径存在永生，Closed rogue 每 500ms 杀隧道 → record=closed 期间 wire 间歇可用（guest 实测 UP/死交替），rogue gate 不可达不可管理，状态永不自愈 | night-05 修复面回归（C3） | 已修复（night-06，实机复验双抛收敛+wire 稳定；含 disown 补丁——败者 drop 曾删胜者 record 致全灭） |
| 027 | S4 | 未收割 ssh 僵尸被 pidfile 判活（kill(pid,0)+start token 双双被僵尸骗过）→ ensure 永久短路，gate Open 但 wire 死（机制探针+实机端到端双验证）；另记 ensure/reap 竞态窗口 | night-05 修复面回归 | 已修复（night-06，实机复验 kill -9 后 1s 重生） |
| 026 | S4 | 孤儿 ssh -R 超出 pid 文件管辖即无人能切（closed=wire down 依赖单文件存活；F-025 现场实测遗留） | night-05 实机验证 | 已修复（night-05，实机复验） |
| 025 | S4 | 处女 profile 的 up 误报失败：proxy/ 目录缺失使 gate.pid/log 写入 ENOENT（守护已 spawn 但 CLI 走回退且回退同败） | night-05 实机验证 | 已修复（night-05） |
| 024 | S3 | v0.4.0 终稿未过 CI：fmt 11 处红 + lima 测试断言引用已删除的 hostname 字段恒失败（R3"基线绿"不实） | night-05 基线核验 | 已修复（night-05） |
| 023 | S5 | 深路径 profile setup 撞 UNIX_PATH_MAX：limactl fatal 原样抛出，creance 无预检 | R3→0.3+D1 | 已修复（night-05） |
| 022 | S4 | 0.4 身份声明差距：username 未接线（宿主用户名镜像进 guest）/load_or_create 读失败重置身份/credentials 探针假 PASS | R3→0.4+E1 | 已修复（night-05，①实机复验） |
| 021 | S4 | tunnel stop() 盲杀 pid 文件进程：pid 复用窗口误杀同 uid 任意进程（实测 sleep 被杀） | R3→0.3+C6 | 已修复（night-05） |
| 020 | S2 | guest 内一条无密码 sudo 撤销 0.3 拓扑强制：OUTPUT ACCEPT 后直连 1.1.1.1 得 301（实测逃逸） | R3→0.3+D/E | 已修复（night-05，实机复验） |
| 019 | S4 | gate-daemon SIGKILL 后 record 残留：up 全部短路+孤儿隧道 wire 无法关（fail-open）+escape 探针假 PASS（实测全链） | R3→0.4+C3 | 已修复（night-05，实机复验） |
| 018 | S5 | precheck_depth 把字符串字面量括号计入深度：密码含 129 个 [ 的合法订阅被拒（Go 接受） | R2→001+A1 | 已修复（night-04） |
| 017 | S4 | 204/304 无 body 挂满 deadline（refresh+304 场景 60s 失败）；Go 按状态码立即完成 | R2→night-02/B2 | 已修复（night-04） |
| 016 | S4 | 011 残留：结构错 YAML 假 PASS + merge key 骗术（serde_yaml 不展开 lima 展开，探针被骗） | R2→011+E1 | 已修复（night-04） |
| 015 | S5 | 004 尾斜杠启发式被尾随空白/反斜杠绕过（4 变体误放行） | R2→004 | 已修复（night-04） |
| 014 | S4 | 并发 import 丢失更新（双成功单存活）+ select_and_apply 非原子残留不一致 | C1 | 已修复（night-03） |
| 013 | S4 | SOCKS5 凭据 as u8 截断（ULEN=44 实测），target 有校验凭据没有 | B1 | 已修复（night-03） |
| 012 | S5 | 非字符串键节点整拒（Go map[any]any 显式接受），issue.name 丢失 | G2 | 已修复（night-03） |
| 011 | S4 | 探针质量：mounts 计数 3 种 YAML 骗术/sock-abstract 硬编码 PASS/env-credentials 恒误报 | E1+E2 | 已修复（night-03；误报项即 grep 模式对齐 STRIPPED 未动，属共同窄设计） |
| 010 | S2 | limactl() 自删 LIMA_HOME→全部 VM 操作落全局 ~/.lima，profile 隔离失效+探针脱节 | D2+E1 | 已修复（见 FIX-NIGHT-01 提交） |
| 009 | S2 | fetch.rs 缺 https 策略：明文订阅/userinfo/5 跳全被接受（Go 全拒）→订阅凭据对出口明文 | B4 | 已修复（见 FIX-NIGHT-01 提交） |
| 008 | S4 | gate 四处漂移：grant 无 Checking 前置/reason 200B 上限对 CJK 失效/token 非恒时比较/exit_policy 变化不重开 | C3+C4 | 已修复（FIX-NIGHT-02） |
| 007 | S2 | SSRF 守卫漏 IPv4-mapped IPv6：::ffff:127.0.0.1 绕过检查，真实 mihomo 规范化后拨号本机 | B4 | 已修复（见 FIX-NIGHT-01 提交） |
| 006 | S4 | egress 五类宽容接受：chunked EOF/CRLF 重同步/双 CL/垃圾 CL/半截头均当成功（Go 严格拒绝） | A7+A8+B2+B3 | 已修复（FIX-NIGHT-02） |
| 005 | S5 | DNS unpack 接受 0x40/0x80 保留前缀标签（>63），miekg 拒绝；pack rdlen 截断地雷 | A6 | 已修复（night-03） |
| 004 | S5 | config 校验三处 Go 漂移：时区目录名/IPv6 括号/尾斜杠 | A5 | 已修复（night-03） |
| 003 | S4 | 数字 mport 被拒、Go case int 明确支持（yaml_to_json 丢整数性） | A4 | 已修复（FIX-NIGHT-02） |
| 001 | S3 | 订阅 YAML 深嵌套 O(n²) CPU：1MiB 烧 406s，8MiB 外推约 7 小时 | A1 | 已修复（见 FIX-NIGHT-01 提交） |
| 002 | S4 | 超 u64 整数标量拒绝整份订阅（Go 版回退 float64 接受） | A1 | 已修复（FIX-NIGHT-02） |

（空 — 等待第一轮夜间运行）
