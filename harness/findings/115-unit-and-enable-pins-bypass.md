# FINDING-115: F-109 钉仍可绕：变量拼路径 `SD=/etc/system""d/system; cat >"$SD/x.service"`、缩进 ` cd`+`cat >rel`、enable 行保留但下一行 `systemctl disable`、enable 行包进 `: <<'NOEN'` heredoc 全绿

- **编号**: 115
- **严重度**: S5（质量：守护/测试强度不足，需代码变更才可触发；无运行时可达路径）
- **攻击面**: F-109 修复面（provision.rs:118, 300-372）
- **发现者会话**: r30-auditor
- **状态**: 待修复

## 机理

`systemd/` 计数、`cat > `(带空格)计数、`\ncd ` 禁都是子串；引号拆分 `system""d` 与 `cat >"` / ` cd` 均不命中。enable 整行相等只证明该行存在，不证明未被后续 `disable` 撤销或未被 heredoc 吞掉。

## 复现

```sh
CREANCE_REPO=$HOME/r30-wt ONLY="NC-UNITvar NC-UNITcd2 NC-ENdisable NC-ENheredoc" python3 harness/tools/r30-negative-controls/run.py   # worktree 放 $HOME（git worktree add --detach $HOME/r30-wt v0.6.22）；用例见 harness/tools/r30-negative-controls/cases.py
```

期望：每个用例至少一项测试或 clippy 红。实际：

| 用例 | 注入 | 测试（fmt+cargo test --workspace+clippy -D warnings；裁判双跑） | 后果 |
|---|---|---|---|
| NC-UNITvar | LOCKUNIT 后加 `SD=/etc/system""d/system` + `cat >"$SD/net-tune.service" <<'TUNE'`（第二 unit），enable 后加 `systemctl enable net-tune.service` | 绿×2 | 任意 root unit 在 boot 时跑（可在 egress-lock 后 flush 规则） |
| NC-UNITcd2 | ` cd /etc/system""d/system` + `cat >net-tune.service` + ` cd /` | 绿×2 | 同上 |
| NC-ENdisable | enable 行后加 `systemctl disable egress-lock.service >/dev/null` | 绿×2 | 锁闭 unit 不开机启动，重启后无 iptables 锁闭 |
| NC-ENheredoc | enable 行前后包 `: <<'NOEN'`…`NOEN` | 绿×2 | enable 不执行，同上 |

## 已尝试未通的路（对照红）

已拒：r29 `cd`+相对、`./` 中缀、允许集追加/push（NC-UNITcd/UNITdot/ALLOWapp/ALLOWpush 红）；Tab/双空格 `cat\t>` 写入 rules.v4 外路径——`cat > `==3 精确计数不受影响但能新增 cat 而不计数，归入本条同机理。

## 建议

以 `sh` 实执行脚本（stub systemctl 记录调用序列）断言最终 enable 集合==`{egress-lock}`、disable 为空；禁 `""`/`$` 出现在路径型参数；`cat` 计数改正则 `cat\s*>`。
