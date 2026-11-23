# FINDING-109: F-101 钉仍只数形状：enable 行注释掉、`cd /etc/systemd/system` + 相对路径第二 unit、`/etc/systemd/./system/` 第二 unit、verbatim 13-arg 后追加第 14 条 / `allowed.push` 全绿

- **编号**: 109
- **严重度**: S5（质量：守护/测试强度不足，需代码变更才可触发；无运行时可达路径）
- **攻击面**: F-101 修复面（provision.rs unit 计数；gateprobe.rs 允许集钉）
- **发现者会话**: r29-auditor
- **状态**: 已修复（main-session，实机复验）：enable 行整行相等、\ncd 禁、cat > ==3、systemd/ 宽计数==1、允许集整行相等+allowed 计数钉

## 机理

`systemd/system/` 计数是子串计数：`./` 插段、`cd` 后相对文件名都不含该子串；enable 行只被 `contains("systemctl enable egress-lock.service")` 检查，`# systemctl enable …` 仍满足。允许集 "VERBATIM" 实为 `contains(expected)`——前缀相等即可，尾部追加任意 `-e` 条目通过。

## 复现

```sh
CREANCE_REPO=$HOME/r29-wt ONLY="NC-ENcomment NC-UNITcd NC-UNITdot NC-ALLOWapp NC-ALLOWpush" python3 harness/tools/r29-negative-controls/run.py   # worktree 放 $HOME；用例定义见 harness/tools/r29-negative-controls/cases.py
```

| 用例 | 注入 | 测试（cargo test --workspace + clippy -D warnings；裁判双跑） | 后果 |
|---|---|---|---|
| NC-ENcomment | `systemctl enable egress-lock.service >/dev/null` → 前加 `# ` | 绿×2 | unit 写入但不启用，重启后无规则 |
| NC-UNITcd | daemon-reload 前 `cd /etc/systemd/system; cat > net-tune.service <<'TUNE'`（`ExecStart=/usr/sbin/iptables -I OUTPUT -j ACCEPT`，After=egress-lock）+ enable | 绿×2 | 第二 unit 放行全部出站 |
| NC-UNITdot | 同上，路径写 `/etc/systemd/./system/net-tune.service` | 绿×2 | 同上 |
| NC-ALLOWapp | `grep -vxF {grep_args})` → `grep -vxF {grep_args} -e '-A OUTPUT -p tcp -j ACCEPT')` | 绿×2 | 探针允许任意 tcp 放行规则存在 |
| NC-ALLOWpush | NAT 循环后 `allowed.push("-A OUTPUT -p tcp -j ACCEPT".to_owned())` | 绿×2 | 同上 |

## 建议

允许集：截取 `grep -vxF` 与 `)` 之间整段做全等；unit：在临时根执行 bootstrap 后枚举 `systemd/system` 下文件并断言集合 == {egress-lock.service} 且 `multi-user.target.wants` 链接存在；enable 钉改为行首锚定。
