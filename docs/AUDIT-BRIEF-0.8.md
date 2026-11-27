# 0.8 外部审计任务书（筹备稿，2026-11-27）

## 背景与规模

自 R32（v0.6.18）以来，**整个 0.7.x 系列（v0.7.0–v0.7.28，12 个特性
版本）从未经过一轮外部审计**——期间只有变异注入矩阵自审（抓到过
F-A1/F-A2 级真 bug，证明自审有效但非独立）。0.8 审计面 = `git diff
v0.6.18..main` 全量，核心新增面：

| 面 | 版本 | 审计要点 |
|---|---|---|
| 浏览器进 guest + 四元组指纹探针 | 0.7.0 | CfT 供应链 sha256 钉；指纹判词 fail-closed 边界 |
| OAuth 通道 | 0.7.1 | Xvnc/noVNC loopback 纪律；ssh -L 空闲口转发 |
| 时区跟随出口 | 0.7.2 | ~/.creance-tz 写盘链；auto 判词豁免 |
| identity-reset | 0.7.3 | 运行中拒绝；指纹整体轮换完整性 |
| Bundles 双层加密 | 0.7.4 | argon2id/XChaCha20-Poly1305 参数；导入白名单 |
| persona 原子切换 | 0.7.5 | 暂存式换回的事务性 |
| 防越权层 | 0.7.6 | .owner 属主绑定；权限探针 |
| 整机迁移 | 0.7.7 | 路径遍历拒收矩阵 |
| 手机审批 | 0.7.8 | 批条 sha256 键控；Telegram 通道经代理栈 |
| vsock 数据面/控制面 | 0.7.19/21 | F-A2 桥死修复；F-A1 双端口争抢；macOS cfg 门控 |
| keychain 引用 | 0.7.25 | 秘密永不落盘不变量；回填防线 |
| 声明式重建 | 0.7.26 | 种子派生不可反推；apply 纯落盘 |
| 信誉探针/指纹注入 | 0.7.27/28 | advisory 不定罪纪律；MAIN world 注入面 |

## 审计纪律（沿用 R 系列）

- 审查员只立案不修复；产出进 `harness/findings/` + `harness/tools/`。
- 对抗性变异验红是标准动作；每个 finding 必须可复现。
- 威胁模型以 `docs/THREAT-MODEL.md` 为准——A 类面按反逃逸纵深审，
  B 类面按文档承诺的诚实边界审（超出承诺的检测面不算 finding）。

## 已知残余（审计员应评估而非重新发现）

1. ACPI 表 "BOCHS" OEM 字符串、chassis type、virtio-net/9p 设备串——
   qemu 工具链边界，需 qemu patch 级工程；评估其 A 类暴露权重。
2. Lima/vz 无 SMBIOS 注入面（lima#932）——macOS 侧统一 Apple 指纹，
   评估批量关联可行性。
3. machine-id 重建随机（apply 残余）——评估是否该种子化。
4. qemu `-name creance-*`、ssh HostKeyAlias 的 ps 可见串——已有定论
   （运维可读性优先），评估是否推翻。
5. B 类 L2（非浏览器客户端 TLS 指纹）——记档暂缓，评估触发器是否
   已满足。
6. 桥接管瞬间端口竞争依赖 guest 侧 Restart=always 自愈——评估竞态
   窗口的实际可利用性。

## 审计轮组织建议

体量远超单轮：建议拆 3 轮——
- **R33 边界层**：egress/lockdown/vsock/隧道/探针（A 类核心）
- **R34 凭证层**：keychain/bundles/审批/种子派生（秘密生命周期）
- **R35 产品层**：provision/apply/persona/serve/Tauri（实现质量+注入面）

## 0.8 其他筹备项

- [x] rustdoc/MSRV/semver-checks 入 CI（v0.7.18 已完成）
- [ ] edition 2024 迁移决议（MSRV 1.88 兼容，待拍板）
- [ ] 特性冻结声明（0.8 起只修不增）
- [ ] 审计配额确认（子会话 probe）

## 执行进度（2026-11-22，主模型独立化自审——外部配额不可用）

**R33 边界层：已完成（v0.8.0）**。通读+变异矩阵抓三枚真 bug
（F-R33-1 splice EOF 自旋/F-R33-2 listener fd 双关/F-R33-3 写死
读吞），全部修复+socketpair 回归测试+变异验证+钉武装。
残余记档：gatebridge 孤儿清扫缺口（小）、实机 echo 复验待新
provision 实例。

**R34 凭证层：已完成（v0.8.1）**。secret/store/identity/bundle/
approve 全通读。修三枚：F-R34-4 bundle 主密码支持 keychain 引用、
F-R34-6 persona 快照目录 0700、F-R34-3 原子性注释纠偏。approve/
bundle 密码学无发现。

**R35 产品层：进行中**。已扫 apply.rs/serve.rs/approve 面——
F-R35-1（apply 缺批条）已修入 v0.8.1。待扫：diagnose.rs、
escape.rs、evidence.rs、cmds/vm.rs、workbench.html JS、qemu/
lima 驱动面。serve.rs 加固记档项：Host 头校验（DNS rebinding 对
GET 信息泄露面，低危）。

