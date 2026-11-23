# FINDING-101: 允许集 `-e '` 精确计数与 “unit 文件写唯一” 都只数形状——替换条目/条目内嵌换行、`tee`/无空格 `cat >` 第二 unit 全绿

- **编号**: 101
- **严重度**: S5（质量：CHANGELOG [0.6.20] "exactly one unit file write, and the probe's allowset is counted exactly (any extra entry, e.g. bare tcp, bumps it)" 只覆盖“追加”形）
- **攻击面**: F-097 修复面（crates/creance/src/escape.rs 允许集测试、crates/creance-vm/src/provision.rs unit 计数）
- **发现者会话**: r28-auditor
- **状态**: 待修复

## 复现

```sh
CARGO_TARGET_DIR=$HOME/r28-wt-target CREANCE_REPO=$HOME/r28-wt ONLY="NC-ALLOWrep NC-ALLOWnl NC-UNITns NC-UNITtee" sh harness/tools/r28-negative-controls/run.sh
```

| 用例 | 注入 | 测试 | 后果 |
|---|---|---|---|
| NC-ALLOWrep | 允许集 `"-A OUTPUT -p udp --dport 67 -d 255.255.255.255 -j ACCEPT"` **替换**为 `"-A OUTPUT -p tcp -j ACCEPT"` | 绿（20p） | 计数仍 13；`!contains("-e '-A OUTPUT -j ACCEPT'")` 只禁裸 ACCEPT 一种拼写 |
| NC-ALLOWnl | `"-A OUTPUT -o lo -j ACCEPT\n-A OUTPUT -p tcp -j ACCEPT"`（一条目内嵌换行） | 绿 | `-e '` 计数不变，多出一条 tcp 放行 |
| NC-UNITns | daemon-reload 前追加 `cat >/etc/systemd/system/net-tune.service <<'TUNE'`（`>` 后无空格）`ExecStart=/usr/sbin/iptables -P OUTPUT ACCEPT`，After=egress-lock，enable | 绿（65p） | 唯一计数只认 `cat > /etc/systemd/system/` 带空格字面 |
| NC-UNITtee | 同上用 `tee /etc/systemd/system/net-tune.service` 写 | 绿 | 同上 |

对照（红）：NC-SETtcp（追加 tcp 条目）、NC-SETregx、NC-CTNEW、NC-UNITsep（R27 带空格第二 unit）、NC-ESPdropin（drop-in）。

## 建议

允许集测试改为与固定期望列表逐项相等（Vec 全等）；bootstrap 测试对 `/etc/systemd/system/` 路径出现次数（任意写法）计数，或在 CI 中执行 bootstrap 于 chroot/临时根并枚举产出的 unit。
