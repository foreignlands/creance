# STATE — 2026-11-19T06:40:00Z（night-05 修复会话 · 终稿）

## 已完成（R3 全部 5 findings + 修复中发现 3 个新 findings = 8 个，全部修复+实机验证）

- **F-020（S2 逃逸，最高优先）✅ 4a62e79 + 实机复验**：lima `user:` 块（生成用户名+中性 comment；uid 保持宿主镜像——vz virtiofs 无 uid 重映射，这是可写挂载的功能前提，纯数字非身份泄漏）；provision 末尾删 cloud-init sudoers 条目 + `passwd -l` + 清 `~/password`（lima 的 `passwordlessSudo: false` 要求 plain 模式且会把随机密码写进 guest，不可用——provision 清理才是真机制）。实测：`id`=dev39f9e161、`sudo -n` 拒绝（"a password is required" + 密码锁定 L）、sudoers 无条目、直连 000、R3 攻击重放失败。新探针 guest-identity/guest-privilege。
- **F-019 ✅ 2df45da + 实机复验**：spawn_daemon 活性校验（retire_stale_record：record→socket status，死即清理+respawn）；close_and_remove 断线立即 cut；cmd_stop 走退役链；escape gate 探针要求活 daemon、"VM 无 record" 改按 limactl 实际 Running 状态判定（停机实例不再误报）。实测：kill -9 → 探针翻红（"gate record without a live daemon"）→ up 自愈 → 回绿且直连仍 000。
- **F-021 ✅ 9b6e4e1**：pidfile 模块（JSON {pid, started}，legacy 裸 pid 兼容；process_start_token 从 running.rs 提升）；tunnel/gate 全接入。伪造 start-time 的 pid 文件对无辜进程零杀伤（实测回归）。
- **F-022 ✅ 4a62e79 + f544599**：①username 接线（tunnel ssh User=生成名，vsock_user 宿主镜像删除）；②load_or_create 只在 NotFound 生成，读失败拒绝重置身份（目录占位回归测试）；③credentials 探针=profile 目录全量 48-hex 扫描比对已发集合（session token/store auth/gate token），guest 新增 env-hex-tokens 探针。
- **F-023 ✅ b11b543 + 实机验证**：socket_budget 暴露原始预算（可为负），setup 预检 <10 字节即报"路径过深+移浅目录"（mktemp 深路径实测）。
- **F-024 ✅ 6452854**：v0.4.0 终稿漏跑 fmt+ci（11 处 fmt + lima 测试断言过期字段）——基线修复；R3 审查者的"CI 基线绿"结论不实（只跑了部分包）。教训：**实机绿≠CI 绿，任何"最后一笔"编辑后必须重跑完整 ci.sh**。
- **F-025 ✅ b06fb73 + 实机复现**：处女 profile 的 up 误报失败（proxy/ 缺失→gate.pid/log ENOENT，守护实际已 spawn）。pidfile::write 建父目录；spawn_daemon 先 ensure_private_dir。附带：workbench 测试不再假设宿主 17896 端口死寂（limactl 转发 socket 的 CLOSE_WAIT 会把瞬间拒绝变 5s 挂死）。
- **F-026 ✅ 521b58d + dc569a9 修正 + 实机复验**：孤儿 ssh -R（pid 文件管辖外）按特征收割——**特征必须 HostKeyAlias+`-R port:127.0.0.1:port` 双段**（第一版只匹配 alias，实机立即暴露误杀 limactl shell 的每次 ssh 客户端——lima 同样用该 alias 约定，>500ms 的会话被 watchdog 掐死 rc=255）。closed=wire down 不再依赖单文件存活。

## 版本

v0.4.1（tag 待打）：night-05 hardening。测试 148 绿（含 6 个新对抗回归）。CHANGELOG/RELEASES/README（containment contract 新增"No privilege path in the guest"条目）已更新。RELEASES 0.5 主题改为 exit-policy evidence chain（0.4 会话既定方向），multi-env 顺延 0.6。

## 下一步（按序）

1. **R4 回归审查**（用户贴 OPERATOR-PROMPT 给 GLM）：重点=0.4.1 修复面回归（reap 特征绕过/误杀、pidfile start-time 语义、sudoers 摘除的旁路——reboot 后 cloud-init 重放？、scan_unknown_tokens 的绕过形状）、C3 gate 并发黑盒（现有运行实例可用）。
2. **0.5 exit-policy 证据链**（无需用户输入）：gate-open 的 grant 从五项自检升级为出口 IP 实测证据（trace→大陆网段库+国家锚定→Checking 窗口内完成）。
3. 模型驱动逃逸演练（用户接入 GLM 到 VM；ESCAPE-BRIEF.md 就绪）+ Devin 时机（docs/CLOUD-DEVIN.md 就绪）。

## 关键记忆（≤10 条）

1. lima 2.3 的 `passwordlessSudo: false` **要求 plain: true** 且 false 时生成随机密码存 guest `~/password`——非 plain 实例想无 sudo 只能在 provision 里删 sudoers（cloud-init 无条件写 per-user 条目，这是唯一入口）。
2. vz virtiofs 无 uid 重映射：lima 用户 uid=宿主镜像是可写挂载的功能前提——**身份生成只到 name/comment，uid 不动**（数字非身份泄漏）。
3. reap/收割类特征匹配必须验证"唯一性假设"：`HostKeyAlias=lima-<inst>` 是 lima 全家共用的约定（limactl shell 每次客户端都带）——命令行特征要用我们自己拼接的独有段。
4. 测试对"默认端口死寂"的假设会被宿主环境破坏（limactl 持有 17896 CLOSE_WAIT）——测试要么用 port 0 要么显式指向必死端口。
5. R3 的"CI 基线绿"是不可复述结论——审查者的基线必须=完整 scripts/ci.sh 输出。
6. 处女路径（init→setup→up 直通）是 QUICKSTART 首条路径，以后每轮验证都要跑一遍（0.4.1 之前从未直通验证过）。
7. limactl shell 的 mux master 会改名（`ssh: <sock> [mux]`），pgrep -f 匹配不到——判定"是否还有 shell 会话"别依赖 master 匹配。
8. stop 全链（close_and_remove 退役+reap 清扫+limactl stop+delete）实机通过；F-021 新 pid 文件格式实机工作。

## 会话统计

- night-05 修复：8/8（019–026），7 个 commit（6452854→dc569a9），每 commit CI 全绿
- 实机验证：深路径报错、F-020 全链（身份/sudo 拒绝/防火墙/攻击重放）、F-019 kill-自愈链、F-025 复现、F-026 孤儿收割+误杀修正、escape-test 全绿（proxy-path ESCAPE 系无 core 的预期态）
- 累计：26 findings，全修复
- 环境：/tmp/creance-n5 已 stop+delete+清理；无宿主残留（daemon/tunnel 均 0）
