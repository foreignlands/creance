# STATE — R23（第九次收敛判词轮）终稿

- 审查对象：main = v0.6.14（tag 1c55b30）+ 129782d；审查员只记录不修复。
- 未改 crates/、scripts/、docs/；变异全部 cp 备份 → grep -c 注入前后计数 → md5sum -c 还原核验（全 OK）；裁判运行导致的 Cargo.lock 漂移已 `git checkout --` 还原。
- 基线：`sh scripts/ci.sh > /tmp/r23-ci-baseline.log 2>&1; RC=$?` → **RC=0**（177 passed / 0 failed，release build OK）。
- 实机：Linux QEMU（/dev/kvm），v0.6.14 release 二进制，lab 在仓库外，工具全部以 LAB/CREANCE_REPO/CREANCE_BIN 参数化。

## 判词：**不收敛**（新立案 086–089，其中 086 为 S4）

## 复核点

| 核验点 | 结论 | 证据 |
|---|---|---|
| F-082 实机 up#1（供给会话） | 通过：setup RC=0；up#1 RC=0（58s），打印"供给完成"，marker 写入 | r23-real-up/evidence/up1.log |
| F-082 stamp 不可伪造 | 通过：/run/egress-armed root:root 0644，/run root 0755；uid1000 写入 Permission denied；sudo 需密码 | r23-real-up/evidence/facts-up1.log |
| F-082 实机 up#2（restrict=on） | 通过：up#2 RC=0（17s），netdev 含 restrict=on；stamp 随新 boot_id 重写（mtime = ExecMainStartTimestamp） | r23-real-up/evidence/up2.log、facts-up2.log、up2-netdev.txt |
| F-082 已激活 oneshot 的 restart | 通过：已 active 的 egress-lock 上 `systemctl restart` RC=0，ExecMainStartTimestamp 与 stamp mtime 同步前移（13:16:15→13:16:27）——ExecStartPost 会重跑 | r23-restrict-lifecycle/evidence/lifecycle-run2-L3-L4.log（L3） |
| F-082 /run 生命周期 | 通过（QEMU）：每次开机由 enabled unit 重写；Lima 每次 boot 跑 system provision（含同一 restart 腿）——静态推断，未实测（本 VM 无 Lima/arm64） | 同上 + lima.rs:47 |
| F-082 旧实例升级（unit 无 ExecStartPost） | 通过（fail-closed 可接受）：up RC=1，文案"第一道防线未在武装状态…请 creance stop 后 creance setup 重建环境"，VM 已停；marker 保留（下次 setup 重建前恒 fail-closed） | lifecycle-run1.log（L2） |
| F-082 ExecStartPost PATH/工具可用性 | 通过：绝对路径 /usr/sbin/iptables-save、/usr/bin/grep；实机 ExecStartPost status=0 | facts-up1.log |
| F-083 裸 `-A OUTPUT -j ACCEPT` | 通过：netns V02 → fw-down；变异 PRB4 变红 | r23-stamp-netns/netns.log |
| F-083 修复的完整性 | **不通过 → F-086**：限定 ACCEPT（`-o e+` 等 6 种）与盖章后漂移（插入/改策略/flush）均判 fw-armed；实机 D1/D2 restrict=on up RC=0，对照无 restrict 时 tcp/icmp 直连可达 | r23-stamp-netns/netns.log、r23-stamp-drift/evidence/ |
| F-082/083 变异：删 ExecStartPost / stamp 不含规则行 / verdict 删 fw_ok / probe 删裸 ACCEPT 检查 | 通过：NC-EXP、NC-STAMP、NC-FW、NC-PRB4 全变红 | r23-negative-controls/evidence.log |
| F-084 变异：回退旧签名 / verdict 恒 Ok / probe 恒输出 / serve 删 TE 分支 / provision 删 ExecStartPost | 通过（各自主形态）：NC-SIG/F/F2、NC-VOK、NC-PRB、NC-TE/TE2、NC-EXP 全变红；CL 三例、node 钉值、Lima digest 键+值、URL 均变红 | 同上 |
| F-084 守护完整性 | **不通过 → F-087**：13 例全绿（probe else 恒 armed / 反转 / 策略判据失效；marker 写进失败分支或 vm::up 内；mark_provisioned 不写盘；stamp 被覆盖/吞错；restart 腿注释；node 校验门 `if false`） | 同上 + logs/ |
| restrict：marker 删除 | 通过：无 marker up 不带 restrict、verdict 后重写 marker；下次 up restrict=on | lifecycle-run1.log（L1） |
| restrict：up 复用运行中 VM（we_started=false） | 通过：up#B RC=0、同一 qemu pid | lifecycle-run1.log（L0） |
| restrict：we_started=false + mount-missing | 通过：RC=1、"工作区未挂载…请 stop 后 setup"，不停他人 VM（qemu pid 存活），marker 不动 | lifecycle-run2-L3-L4.log（L4） |
| restrict：实例目录 rename | 通过：up RC=1"实例不存在…请先 creance setup"，不新建、不复用 | lifecycle-run1.log（L5） |
| restrict：marker 残留语义 | 通过（记录）：失败的 up（mount-missing、旧 unit fw-down）不删 marker，后续 up 仍带 restrict 且仍 fail-closed；只有 setup 重建清理 | L2/L4 |
| F-085 CHANGELOG 对账 | **不通过 → F-088**：v0.6.14 tag 无自身条目；[0.6.13] 记入 v0.6.14 改动；[0.6.10]/[0.6.11] 各提前一版；3783863、b144b77（含平台收缩）漏记 | 088 复现命令 |
| 门禁矩阵 + 正控 | 通过：POS RC=0；NC-A/B/1/2/3/5/6v 全 RC=1；md5 四文件 OK | r23-gate-matrix/evidence.log |
| 裁判双跑（main 原工具） | **不通过 → F-089**：r14 RC=0×2 但 md5=ac301449（R22 为 2ecbd0c1，期望 id 27→26，已在 SKIP 世界）；r15 RC=101×2（锚点缺失 panic） | r23-judges/evidence.log |
| 裁判双跑（R23 副本，只换可写 flag 路径） | 通过：r14 RC=0×2 md5=2ecbd0c1；r15 RC=0×2 md5=965e444c——与 R22 逐字节一致，产品渲染无回归 | 同上 |

## 邻接面（v0.6.13..v0.6.14 逐文件）

- escape.rs：egress_probe_script/egress_verdict 唯一调用方 main.rs:751-765；guest_script 新签名调用方 main.rs（escape-test）+ r14/r15 裁判（F-089）+ 单测；guest_script 现有文件系统副作用（单测在 /tmp 留 creance-test-flag-<pid>，记录不立案）。
- provision.rs：ExecStartPost 单引号内双引号 grep -E 正则在 systemd 解析下实机工作；restart 腿实测重跑 ExecStartPost。
- serve.rs：TE 任意值、重复/非法 CL → 400，socket 测试存在且变异变红。
- lima.rs：digest 键+值断言变异变红；Lima 后端未实测。
- main.rs：marker 后置在成功路径正确；守护缺口见 F-087。

## 未验证想法

- Lima（arm64/macOS）上 /run stamp 与 restart 腿的真实行为（静态与 QEMU 同源）。
- 首次 L4 尝试中，一个 `Type=oneshot` + `sleep 150` 的额外 unit 使首个 up 的工作区挂载也缺失（原因未查；改为 Type=simple 后正常）。属测试夹具副作用，记录。

## 建议下一轮

修 086 后复跑 r23-stamp-drift D1/D2 与 r23-stamp-netns（期望全部 fw-down / up RC=1）；修 087 后复跑 r23-negative-controls（期望 13 例变红）；修 089 后 main 原裁判应与 R23 副本 md5 一致。
