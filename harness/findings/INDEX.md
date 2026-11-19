# Findings Index

| # | 严重度 | 标题 | 攻击面 | 状态 |
|---|---|---|---|---|
<!-- NNN | S? | 一句话 | A? | 待修复/已修复(commit)/误报 -->
| 014 | S4 | 并发 import 丢失更新（双成功单存活）+ select_and_apply 非原子残留不一致 | C1 | 已修复（night-03） |
| 013 | S4 | SOCKS5 凭据 as u8 截断（ULEN=44 实测），target 有校验凭据没有 | B1 | 已修复（night-03） |
| 012 | S5 | 非字符串键节点整拒（Go map[any]any 显式接受），issue.name 丢失 | G2 | 已修复（night-03） |
| 011 | S4 | 探针质量：mounts 计数 3 种 YAML 骗术/sock-abstract 硬编码 PASS/env-credentials 恒误报 | E1+E2 | 已修复（night-03；误报项即 grep 模式对齐 STRIPPED 未动，属共同窄设计） |
| 010 | S2 | limactl() 自删 LIMA_HOME→全部 VM 操作落全局 ~/.lima，profile 隔离失效+探针脱节 | D2+E1 | 已修复（见 FIX-NIGHT-01 提交） |
| 009 | S2 | fetch.rs 缺 https 策略：明文订阅/userinfo/5 跳全被接受（Go 全拒）→订阅凭据对出口明文 | B4 | 已修复（见 FIX-NIGHT-01 提交） |
| 008 | S4 | gate 四处漂移：grant 无 Checking 前置/reason 200B 上限对 CJK 失效/token 非恒时比较/exit_policy 变化不重开 | C3+C4 | 已修复（FIX-NIGHT-02） |
| 007 | S2 | SSRF 守卫漏 IPv4-mapped IPv6：::ffff:127.0.0.1 绕过检查，真实 mihomo 规范化后拨号本机 | B4 | 已修复（见 FIX-NIGHT-01 提交） |
| 006 | S4 | egress 五类宽容接受：chunked EOF/CRLF 重同步/双 CL/垃圾 CL/半截头均当成功（Go 严格拒绝） | A7+A8+B2+B3 | 已修复（FIX-NIGHT-02） |
| 005 | S5 | DNS unpack 接受 0x40/0x80 保留前缀标签（>63），miekg 拒绝；pack rdlen 截断地雷 | A6 | 待修复 |
| 004 | S5 | config 校验三处 Go 漂移：时区目录名/IPv6 括号/尾斜杠 | A5 | 待修复 |
| 003 | S4 | 数字 mport 被拒、Go case int 明确支持（yaml_to_json 丢整数性） | A4 | 已修复（FIX-NIGHT-02） |
| 001 | S3 | 订阅 YAML 深嵌套 O(n²) CPU：1MiB 烧 406s，8MiB 外推约 7 小时 | A1 | 已修复（见 FIX-NIGHT-01 提交） |
| 002 | S4 | 超 u64 整数标量拒绝整份订阅（Go 版回退 float64 接受） | A1 | 已修复（FIX-NIGHT-02） |

（空 — 等待第一轮夜间运行）
