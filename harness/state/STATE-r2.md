# STATE — 2026-11-19T03:20:00Z（R2 第二轮审查 s01 · 终稿）

## 已覆盖（R2 全部三优先级完成）

### P1 修复回归审查（5 方向，4 findings）

- **004 尾斜杠启发式（8d862d4）** → **F-015 (S5)**：4 个误放行（`…1080/ `尾随空格/tab/CR、`http://…1080\` 反斜杠）——WHATWG 解析器 strip C0/space+`\`→`/` 规范化 vs 原始串 `ends_with('/')` 错位。24 变体双向矩阵其余 20 个全部 match（r2-url-probe）。修法：先 trim_end_matches(<=0x20) 再判定。
- **014 flock（be0c69f）** — 五面审查全过：kill -9 内核释放 ✓；嵌套死锁无实际路径（service::start 不碰锁）✓；symlink 预占同 uid 面 ✓；入口覆盖 7 个写路径全在锁内 ✓；**inode 分裂脑 OS 语义实证**（python fcntl：rm .lock 后双进程各持新 inode 双双拿锁）但 creance 无删 .lock 代码路径——flock-on-file 固有限制记档不立 finding。
- **011 探针（68d9721）** → **F-016 (S4)**：①结构错 YAML（根序列/标量/null、mounts 为 map/str）报 Contained 假 PASS（6 形态，escape-yaml-probe 实证）②**merge key 骗术**：serde_yaml 0.9 不展开 `<<`（探针数 1→Contained），lima/go-yaml v3 标准展开（实际 2 mounts）——检测可绕过。无 panic 面（多文档/recursion Err→Escaped ✓）。修法：结构不可判定→NotEnforced；含 `<<`/锚点→NotEnforced（解析器能力不对齐不硬判）。
- **012 键碰撞（f7611d5）** — 证伪：int `1` vs `"1"` 碰撞方向确定（文档序后者覆盖），dialer-proxy 引用无错乱（黑盒 3 场景）✓。值覆盖系 go-yaml 语义漂移但非字符串键本为垃圾载荷——记档。
- **night-02（5cf4613）+ night-01（f364ab0）** → **F-017 (S4)**：204/304 无 body 挂满 deadline（r2-204 实证 4s REJECT vs 200+CL:0 立即）；真实触发=proxy-refresh+304 协商挂 60s。HEAD 不可达/trailer 安全/CL:0 ✓/HTTP1.0 ✓。gate check_id 6 边界推演全 fail-closed ✓。https-only 后门 env 精确匹配保守 ✓、workbench 路径 http 0.0s 立即拒 ✓。**F-018 (S5)**：precheck_depth 字面量括号误杀（password 129 个 `[` 被拒实测，Go 接受）。

### P2 上轮受限未测

- **B5 DoH 黑盒** — **仍受限**：dns_url 强制 https + rustls `webpki_roots` 硬编码（egress.rs tls_config）——本地无受信证书路径，畸形 DoH 应答不可伪造；真实 1.1.1.1 不会回畸形。维持受限未测；畸形面已有 pack/unpack 单元层覆盖（R1）。
- **C3 gate 并发黑盒** — **结构受限**：`Gate::start` 无任何外部调用方（grep 全仓）——gate 控制面**未接线**到 CLI/VM 生命周期（0.3 路线），运行时实例不存在；gate crate 897 行生产不可达（除自身 tests）。并发黑盒推迟到接线时；F-008 修复当前无运行时暴露面。
- **E3 workbench 黑盒** — **闭环无发现**（起 serve 全 API 模糊）：畸形 JSON 400 ✓；CSRF evil/wrong-port/case 全 403 ✓；chunked（含 no-space 原始字节）后果=空 body JSON 400，无走私面（单请求模型，R1 F2 的 S5 记档可关闭）；2MiB body 提前拒 ✓；http 订阅 502 立即（F-009 生效实证）；CL 谎报挂 10s read timeout 上限（自伤面已知）；路径遍历/杂方法全 404 ✓。

### P3 新攻击面快扫

- **install.sh** — 引号纪律完整无命令注入；`mkdir -p` 缺 `--`（PREFIX 以 `-` 开头→失败即停，无害）。
- **fetch-proxy-core.sh** — 无 sha256 pinning（信任 github release+TLS；dev-only 脚本）——S5 记档不立 finding；管道失败链 set -e 兜住。
- **lima.rs 模板** — timezone/locale 经 serde_yaml 结构化写入（注入面被序列化+config 严格正则双层挡住）✓；`provision_script(locale)` 是唯一 shell format! 拼接——唯一调用链上游有 is_locale 正则 ✓，函数本身不校验（防御深度记档：pub fn 未来调用方须自校验）；guest 内 `curl|bash` bootstrap 为设计意图（guest 面）。
- **serve×proxy-start 并发交叉** — 7 个 store 写路径锁覆盖终查闭环 ✓；/api/check 只读无锁 ✓。

## 进行中

无。R2 任务单（三优先级）全部完成。

## 下一步（按序 3 条）

1. **修复会话（night-04）**：按 INDEX 修 015/016/017/018（修法建议在各 finding 文内）。
2. **gate 接线时**（0.3 VM 网络面）：C3 并发黑盒 + F-008 的运行时验证一并做——现在做无对象。
3. **B5 永久受限说明**：除非上游提供 test-only TLS 配置注入（如 `#[cfg(test)]` 换 roots）或 DoH 加 http:// 测试形态，畸形 DoH 应答面只能停在单元层。

## 关键记忆（≤10 条）

1. R2 四个 findings 中三个是修复引入的边角（015/016/018）、一个是 R1 漏测原有时序缺陷（017）——**回归审查性价比高**：修复者自标的两个 review 候选（尾斜杠/flock）一个出 finding 一个证伪。
2. 004 启发式修法一行：`s.trim_end_matches(|c: char| c <= ' ')` 后 ends_with('/')（对齐 WHATWG trim）。
3. 016 merge key 是解析器能力差的通类骗术窗口：**探针解析器必须与被检测系统能力对齐，不对齐的文件应 NotEnforced**——比逐特性堵更稳。
4. 017 修法：request_bounded 已有 status，`status==204||304`（+method HEAD）传 read_body 走零体路径。
5. 018 修法权衡：阈值 128→512 拓宽误杀空间但恶意 20KB 拒绝时间回到 ~3s（F-001 曲线）——需实测再定；in-string 跳过（3 状态机）是精确解。
6. flock 分裂脑（rm→新 inode 双持锁）OS 实证成立；flock-on-file 方案固有，触发需外部删 .lock（当前无路径）。
7. gate 未接线 = 897 行死代码面（生产不可达）——C3/F-008 运行时验证全部推迟到 0.3。
8. workbench chunked no-space"绕过"后果=空 body JSON 400（R1 记档可关）——审查判断要追到实际后果而非绕过本身。
9. r2 工具三件：r2-url-probe（Go 语义基准列驱动比较式审查）、r2-204（保持连接服务器）、escape-yaml-probe（复刻探针判定逻辑）。
10. B5 的 rustls webpki roots 硬编码 = 本地伪造 DoH 应答永久不可行（除非上游开 test 注入口）。

## 会话统计

- R2-s01 发现数：4（015 S5、016 S4、017 S4、018 S5）
- 累计：18 findings（R1 14 + R2 4）
- P1 5 方向 / P2 3 项 / P3 4 项 全部覆盖
- 工具新增：harness/tools/r2-url-probe/、a7-response-probe/src/bin/{r2-204.rs}、a1-yaml-bomb/src/bin/escape-yaml-probe.rs
- CI 基线：R2 开工时验证全绿（仓库只读保持）
- **建议**：R2 主体完成；修复会话处理 4 个新 finding 后，可考虑 R3 聚焦 0.3 接线后的 gate/VM 网络面（现在无对象）。
