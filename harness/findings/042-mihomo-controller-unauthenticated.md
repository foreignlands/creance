# F-042 — mihomo external-controller-unix 零认证：同 uid 单请求翻转 egress（mode=direct / MATCH,DIRECT 重载），出口证据预言机被运行时劫持且零文件痕迹

- **严重度**：S4（边界=同 uid；**非 Rust 漂移**——Go 原版同形，见下；按 F-037 的"同 uid 无凭证进程"定级逻辑可议 S2，留给 0.6 硬化权衡）
- **攻击面**：B1（R6 未验证想法→本轮实机证实）· F-038 单源边界再收窄
- **状态**：待修复（建议 0.6）
- **基线**：v0.5.2 `281899c`
- **复现**：实机（本机 launchd 真实核心 v1.19.34 + 临时 profile /tmp/r7-b1，实验后已全部清理，无残留进程/目录）

## 结论一句话

runtime.rs 生成的核心配置（`crates/creance-proxy/src/runtime.rs:90`）只设 `external-controller-unix` 路径、**不设 `secret`**——mihomo 控制器零认证。socket 目录 0700 + socket 0600（`service.rs:217-218` ensure_private_dir）把边界限定在**同 uid**——与 F-037 修复时 gate 的威胁边界完全一致，但 gate 平面已内存化 token fail-closed，**enforcement 平面的控制通道却是零凭证全权**：同 uid 无凭证进程可单请求翻转 egress 并让 gate 的出口证据"通过"，且所有磁盘审计面（config.yaml/sources.json/戳）保持诚实原样。

## 实机证据（全部 HTTP 层实测，无凭证、无文件改动）

1. **零认证读**：`curl --unix-socket /tmp/cage-proxy-501-<hash>/control.sock http://localhost/version` → `{"meta":true,"version":"v1.19.34"}`；`GET /configs` → mode/mixed-port/interface-name 全量（无 Authorization 头）。
2. **单请求翻 direct**：`PATCH /configs {"mode":"direct"}` → HTTP 204；`GET /configs` → `mode=direct`；**磁盘 `proxy/config.yaml` 仍 `mode: rule`**——运行时分歧文件不可见。
3. **出口证据预言机被劫持**：劫持后经核心采样 `https://1.1.1.1/cdn-cgi/trace`（gate::open 的 observe 路径）→ `ip=142.249.39.221 loc=US`（宿主真实出口）。对照：未劫持时该样本走不可达假节点 → **无证据（拒绝）**。即零凭证 API 把"无证据"变成"任意证据"——gate::open 的 exit_consistency 判定完全随核心运行时状态走（F-038 已声明"证据路径与 wire 同源"，本实验证明该源本身可被同 uid 无痕重定向）。
4. **全量配置重载（核心内差异化路由可行）**：`PUT /configs?force=true` 受 mihomo SAFE_PATHS 限制（只接受 `allowed paths: [/tmp/r7-b1/proxy]`）——但该目录同 uid 可写：写入 `evil-reload.yaml`（`rules: [MATCH,DIRECT]`、组=DIRECT、同端口同认证）→ PUT 该路径 → HTTP 204 → `GET /rules` → `Match→DIRECT`；采样仍返回宿主出口。**MATCH,CAGE 单组路由被运行时替换为直连，无重启、无锁、无文件痕迹**（evil yaml 放在被审计目录里是唯一痕迹，用完即删则无痕）。
5. **check_running 可观测但不设防**：`service.rs check_running` 查询运行时 API（port/interface/selection/unified-delay），证明运行时分歧**可**被检测——但 mode/rules 不在其检查集，且无任何持续轮询；一请求翻转+恢复无痕迹。

## Go 对照（非漂移）

`claude-cage-ref/internal/managedproxy/store.go:304`：Go 生成同样形状——`external-controller-unix` 有、`secret` 无；`store_test.go:128` 明确断言 TCP 控制器为 nil（unix-only 是两版共同的设计选择）。**移植忠实复现了 Go 的暴露**——按 S5 漂移口径应记"无漂移"；按 F-037 的定级逻辑（同 uid 无凭证进程不可驱动安全平面）这是比 F-037 关闭的洞更强的剩余面：F-037 堵的是 gate 控制面，本洞在 enforcement 面本身。定 S4，建议 0.6 授权集对齐时一并硬化。

## 威胁模型与支配性说明

- 可达性：guest **不可达**（socket 在宿主 /tmp，目录 0700；guest 唯一出口是 17896 mixed-port，带 cage:auth 认证）。攻击者=同 uid 宿主进程（含无凭证进程）。
- 支配性：同 uid 本可改 store/config/杀服务——但那些路径要么被 applied()/check_running 的对账察觉、要么留下文件痕迹、要么需要 launchctl 重启。**API 路径是唯一无痕、即时、可逆、免锁（无 store_lock）的路径**——支配性论证不能覆盖它。
- 与 F-038 的关系：F-038 声明的边界是"节点以外的路径已封死（TLS/单 MATCH/parse_trace）"。本洞收窄其结论：**核心自身的路由诚实性**对同 uid 无凭证进程是开放变量，"rests on the subscription's routing honesty"之下还压着一层"rests on the controller's inaccessibility"，后者当前只由 unix 文件权限承担。

## 修复方向（记录，不实现）

1. runtime.rs 生成配置加 `secret`（复用 store.auth 或独立 token）；`service.rs check_running` 与其它 API 调用方带 Bearer。一行配置+头部，闭环。
2. readiness 检查集补 `mode`（与 config.yaml 对账）——即使未来出现其它无痕翻转通道也能被 readiness 察觉。
3. 若 0.6 走"二源交叉"，源二必须**不经核心**采样（直连对照），否则本洞把二源一起劫持。

## 清理声明

实验核心已 `proxy-stop`（launchd 无 cage 服务），/tmp/r7-b1、evil yaml、全部 /tmp/cage-proxy-501-* 目录（含 6 个历史会话残留死 socket 目录，逐个 connect 验死后删除）均已清除；无 mihomo 进程残留。
