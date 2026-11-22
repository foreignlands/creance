# FINDING-082: v0.6.13 的 fw-armed 探针以无特权 guest 用户、PATH=/usr/bin:/bin 运行 `iptables -L`——永远输出 fw-down：Linux 上每一次 `creance up` 都在完整供给后被自己的守门判失败并停机，provisioned 标记永不写入，restrict=on 第二道防线永不武装

- **编号**: 082
- **严重度**: S4（正确性/可用性：fail-closed，未破坏隔离契约；但 v0.6.13 在 Linux 上 `up` 100% 失败、按提示 `setup` 重建后仍 100% 失败，且 F-081 修复的目标——restrict=on 武装——永远不会发生）
- **攻击面**: H1 / F-081 修复面（a24b26b main.rs:754-772）
- **发现时间**: 2026-11-22T07:20Z
- **发现者会话**: r22-auditor（R22 第八次收敛判词轮）
- **状态**: 已修复（main-session，实机复验）

## 复现（必须）

```sh
# 实机：本 VM（KVM + qemu），v0.6.13 release 二进制，全新 profile
LAB=~/r22-lab; mkdir -p $LAB && cp target/release/creance $LAB/ && cd $LAB
export CREANCE_CONFIG=$LAB/prof/config.json
./creance init && ./creance setup --memory 4 --cpus 4     # setup RC=0
./creance up                                              # up#1：首次供给
LAB=$LAB sh harness/tools/r22-fw-armed/race.sh             # up#2 + 竞态取 guest 内证据
sh harness/tools/r22-fw-armed/netns.sh                     # 宿主侧逐字回放探针行
# 证据：harness/tools/r22-fw-armed/evidence/{s,up1,up2,race}.log、netns.log
```

实测（v0.6.13 / a24b26b）：

```
up#1 RC=1 (2m23s):  guest 第一道防线（iptables 锁闭）未在武装状态——restrict=on 下的绿色直连判定不可信，按未验证拒绝交付，
                    VM 已停止；请 creance stop 后 creance setup 重建环境。探针原始输出："tcp-blocked\nicmp-blocked\nfw-down\n"
up#2 RC=1:          同上，逐字相同
guest 内（up#2 停机前竞态取证）:
  id: uid=1000(dev44febe1f) gid=1000(dev44febe1f) groups=1000(dev44febe1f)
  /usr/bin/iptables: No such file or directory；/usr/sbin/iptables -> /etc/alternatives/iptables -> /usr/sbin/iptables-nft
  探针行逐字（登录 PATH 下）→ fw-down；带 /usr/sbin 的 stderr：
     iptables v1.8.10 (nf_tables): Could not fetch rule set generation id: Permission denied (you must be root)
  sudo -n → "a password is required"（F-019 之后 guest 无特权路径，属设计）
  /etc/iptables/rules.v4 = :OUTPUT DROP [0:0] + lo/ESTABLISHED/…；egress-lock.service active；直连 1.1.1.1:443 blocked
实例目录（up#2 后）: 无 provisioned 文件 → runner::build_args 永不加 restrict=on
宿主 netns 回放（root，产品形态规则表已加载）:
  P1 PATH=/usr/sbin:/usr/bin:/bin → fw-armed
  P4 PATH=/usr/bin:/bin           → fw-down    （探针自己 export 的 PATH 里没有 iptables）
  P5 uid 1000，完整 PATH           → fw-down    （Permission denied (you must be root)）
```

- **期望**: 供给成功、第一道防线确已武装（规则表 OUTPUT DROP 已加载、egress-lock active、直连被拦）时，up 守门通过，写 provisioned 标记，下次启动 restrict=on 武装（F-081 修复所述行为）。
- **实际**: 探针行有两个各自足以致命的缺陷：(1) 探针首行 `export PATH=/usr/bin:/bin`（F-062 防 PATH 劫持），而 iptables 只在 /usr/sbin——命令找不到；(2) 即便路径对，guest_script 以生成的无特权用户经 ssh 运行（vm.rs:357-393），`iptables -L` 需要 CAP_NET_ADMIN，nft 后端直接 Permission denied，guest 用户无 sudo（provision.rs:179-183 有意删除）。`2>/dev/null` 吞掉两种错误，`grep -q` 失败 → 恒 fw-down → main.rs:766 判失败 → stop_vm → RC=1。用户按文案 `creance setup` 重建后路径相同，无出路。因为守门永不通过，main.rs:789 的 mark_provisioned 永不执行，restrict=on 永不武装——F-081 修复把"第二道防线不可观测"变成了"第二道防线永不存在 + 环境不可用"。
- **复用路径**：we_started=false（VM 已在跑）时守门同样恒失败，main.rs:767 无条件 stop_vm——任何对健康运行中 VM 的 `creance up` 都会把它停掉。
- **声明面**：F-078..081 条目与 INDEX 状态写"已修复（main-session，实机复验）"；对 081 而言实机首次 up 即失败，该"实机复验"不可能在 a24b26b 的二进制上成立。

## 根因猜测

crates/creance/src/main.rs:754：`if iptables -L OUTPUT -n 2>/dev/null | head -1 | grep -q 'policy DROP'; then echo fw-armed; else echo fw-down; fi`——与同一脚本 :751 的 `export PATH=/usr/bin:/bin` 及 guest_script 的无特权传输（crates/creance-vm/src/vm.rs:369-377，ssh 到生成用户）冲突。没有任何测试执行这段 shell（见 F-084：NC-FW/NC-FW2 全绿），所以 CI 全绿放行。

## 未验证想法

- macOS/Lima：guest_script 走 `limactl shell <inst> sh -s`，以宿主用户名的 guest 用户运行，provision 同样删 sudoers 授权（lima.rs:71/175/229）——按代码同样恒 fw-down、每次 up 失败。本机无 limactl，未实跑。

## 建议修复方向（供第二天的人参考，非结论）

无特权可读的正向证据替代 `iptables -L`：例如供给时由 root 把加载后的规则摘要（`iptables-save` 的 OUTPUT 段 sha256 或策略行）写到 root 拥有、用户可读的文件，并由 egress-lock.service 在每次启动 restore 后刷新；up 读该文件并与宿主渲染值比对。或在 guest 内放一个 root 拥有的最小只读状态出口（不可引入新的特权路径）。无论哪种，都需一条真实执行探针 shell 的测试（或 lab 自动化）防止再次"恒假"。
