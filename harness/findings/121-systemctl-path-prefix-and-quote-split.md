# FINDING-121: F-115 行白名单可绕：`/bin/systemctl disable egress-""lock.service`（非行首 `systemctl`、unit 名引号拆分）关掉锁闭单元；`printf … > /etc/system""d/system/net-tune.service` 写第二个 root unit 并 `/bin/systemctl enable` 全绿

- **编号**: 121
- **严重度**: S5（质量：守护/测试强度不足，需代码变更才可触发；无运行时可达路径）
- **攻击面**: F-115 修复面（crates/creance-vm/src/provision.rs systemctl/egress-lock 行白名单 + `cat >`==3）
- **发现者会话**: r31-auditor
- **状态**: 待修复

## 机理

白名单只检查 trim 后以 `systemctl` 开头的行与含 `egress-lock` 子串的行；绝对路径 `/bin/systemctl`、`env`/`command` 前缀不以 `systemctl` 起头，unit 名可用 sh 相邻引号拼接（`egress-""lock`、`'egress-''lock'`）逃过子串。`cat >`==3 只约束 cat，`printf >`/`cp`/`install` 等写文件动词不受限。对照 NC-ENenv（unit 名未拆分）红、NC-UNITprintf（After= 中未拆分）红，证明仅白名单子串在起作用。

## 复现

```sh
git worktree add --detach $HOME/r31-wt v0.6.23   # worktree 放 $HOME，勿放 /tmp
cd harness/tools/r31-negative-controls
CREANCE_REPO=$HOME/r31-wt ONLY="NC-ENdisable2 NC-UNITprintf2" python3 run.py   # 用例见 cases.py
```

期望：每个用例至少一项测试或 clippy 红。实际（fmt+cargo test --workspace --locked+clippy -D warnings；裁判双跑，见 logs/ 与 logs-ref/；md5 还原 OK）：

| 用例 | 注入 | 测试 | 后果 |
|---|---|---|---|
| NC-ENdisable2 | enable 行后插 `/bin/systemctl disable egress-""lock.service >/dev/null` | 绿×2 | egress-lock 开机不启，guest 无出口锁 |
| NC-UNITprintf2 | LOCKUNIT 后 printf 写 `net-tune.service`（ExecStart=`iptables -I OUTPUT -j ACCEPT`，After=`egress-''lock`）；`/bin/systemctl enable net-tune.service` | 绿×2 | 开机在锁之后插 ACCEPT，出口锁失效 |

## 建议

白名单判定改为“含 `systemctl` 子串的任一行”且先对行做 sh 引号归并（去掉 `""`/`''`）后再匹配；或改为执行式测试：stub systemctl 记录全部调用并断言集合恰为 daemon-reload/enable/restart egress-lock，且 /etc/systemd 下仅出现一个 unit 文件。
