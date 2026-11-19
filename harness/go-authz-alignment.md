# Go 授权集对齐面设计审查（R7-B2 · 只记录，不实现）

基线：v0.5.2 `281899c` · Go 参照 `claude-cage-ref`（只读）· 关联 F-036（0.6 方向）、F-041、F-042。

## 1. 报告绑定维度对照

Go `SafetyReport`（internal/cage/safety.go:35-44）七个维度 vs Rust 0.5 四个：

| 维度 | Go | Rust 0.5 | 差距 |
|---|---|---|---|
| Policy 版本钉 | `Policy == SafetyPolicyVersion`（契约版本） | 无 | 缺——报告契约本身无版本约束，0.6 演进时无法拒绝旧契约报告 |
| ID（report_id） | 非空校验 | `report.report_id == command.report_id` | ✓（对称校验 night-02 已修） |
| CheckID（窗口绑定） | `report.CheckID != g.state.CheckID` 拒 | `command.report_id != inner.check_id` 拒 | ✓ |
| RunID（gate 生命绑定） | `r.RunID != runID` 拒 | `report.run_id == self.run_id` | ✓（night-08 F-036 第一片） |
| **Configuration（config 指纹）** | `r.Configuration != configuration` 拒；configuration 来自 `cfg.Fingerprint()`，check 窗口开启时快照进 gate state | **无** | **0.6 主缺口**——与 F-041 同根：锚点/配置变化不使证据失效。gate.rs SafetyReport 注释已预告此维度 |
| CreatedAt | time.Time：IsZero 拒 / 未来 >1min 拒 / `now ≥ CreatedAt+24h` 拒 | u64：`created_at <= now && now-created_at <= 180s` | 时间窗 Rust 更严（180s vs 24h），但缺**显式零值拒**（F-041 附注：now=0 时 fail-open）与**预铸下界**（见 §2） |
| Checks[] 结构 | 每项 {ID,State∈{passed,failed,unknown},Critical,Evidence,CheckedAt}；重复拒/无效态拒/**任一 Critical 非passed 拒**/必需项 Evidence 非空 + CheckedAt∈[CreatedAt, now+1min] | `BTreeMap<String,String>`：REQUIRED 5 键 == "passed" | 缺 Critical 语义（生产方标记的关键项失败仍放行）、缺 Evidence 证据串、缺逐项 CheckedAt；多出的键静默忽略（Go 校验其 State 合法性） |

必需集：Go 11 项（egress_policy/proxy_transport/dns_transport/guest_settings/browser_settings/filesystem_boundary/management_boundary/fail_closed/udp_policy/ipv6_policy/exit_consistency）vs Rust 5 项（egress_policy/fail_closed/udp_policy/ipv6_policy/exit_consistency）。Rust 缺的 6 项对应 Go 的**实测探针层**（guest 内证据采集），0.5 的证据模块只做了 exit 采样——这是"授权集完整对齐=探针层补齐"的真实工作量所在。

## 2. 时间边界细节（Go 有、Rust 无的三条）

1. **预铸下界**：Go `Grant` 要求 `report.CreatedAt >= g.state.CheckStartedAt`（gate.go:259）——检测开始前铸造的报告（预铸重放）拒。Rust 的 180s 窗口允许最多提前 180s 预铸的报告通过（check 前铸造、check 后重放）。窄但真实。
2. **Renew 重授权**：Go `Renew` 对存储的报告**重新跑一遍 Authorizes(runID, Configuration, now)**（gate.go:274-285）——配置指纹变了、或报告过 24h，renew 即拒。Rust renew 只验 report_id（gate.rs:604-620）——F-041 的"renew 无限续期无硬顶"由此而来。
3. **租期硬顶**：Go `armReportLeaseLocked` 取 `min(now+GateLease, CreatedAt+24h)`（gate.go:287-293）——单份报告的总开放时间被 24h 封顶。Rust OPEN_LEASE 90s/次，无累计上限。

## 3. 三维绑定设计审查（0.6）

三个维度在 Go 中各挡一类攻击：check_id 挡**窗口重放**（跨窗口）、run_id 挡**跨 gate 重放**（跨生命）、config fingerprint 挡**证据与配置脱钩**（换配置不换证据）。0.5 已有前两个；第三个落地时：

- **铸造点**：fingerprint 应由 gate 侧在 `check` 动作时快照（Go 把 `Configuration` 存进 gate state，grant 时比对）——而不是让报告自带一个"声称的"指纹（那是自证）。Rust 落点：`GateInner` 加 `configuration: String`，check 时 `config.fingerprint()`，grant 时 `report.configuration == inner.configuration`。
- **与 F-041 的关系**：指纹绑定只保护**报告**；F-041 的洞在 **gate 状态层**（Unchanged 路径锚点失明）。两者互补不可替代：即使指纹绑定落地，F-041 的开放 gate 仍会带着旧报告继续 renew（renew 不重绑新指纹——Go 靠 Renew 重授权挡住）。**对齐顺序建议：F-041 的 strip_config 修复（状态层）→ renew 重授权（续期层）→ 指纹绑定（铸造层）**。
- **与 F-042 的关系**：三维绑定全部作用在 gate 控制面；F-042 表明 enforcement 面本身（核心路由）可被同 uid 无凭证重定向——指纹绑定绑定的是 config.json 的指纹，而核心运行时可以根本不按 config.yaml 跑。**0.6 若做二源交叉，源二必须绕开核心**（见 F-042 修复方向 3）。
- **Authority 来源**：Go 的 requiredSafetyChecks 是编译期常量、"never supplied by the frontend"（safety.go:40）。Rust 的 `SafetyReport::REQUIRED` 同为常量（gate.rs:102）✓——但 Rust 的 checks 是生产方自证字符串表，0.6 补 6 项时每项都应有**gate 侧可验证的证据形态**（至少：Evidence 非空 + CheckedAt 界），否则 11 项只是字符串游戏的扩编。

## 4. 架构层差异（背景，不属对齐项）

Go 的 `Allows()` 在数据路径逐连接判定（gate.go:297-316）；Rust 0.5 的 gate 纯控制面（wire=隧道升/降）。授权集对齐不改变该架构差——Rust 的对等物是隧道层的 per-connection enforcement（ROADMAP 项）。
