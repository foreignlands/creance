# FINDING-020: guest 内一条无密码 sudo 命令即完全撤销 0.3 拓扑强制 — lima 默认用户持 passwordless sudo，`sudo iptables -P OUTPUT ACCEPT` 后直连外网实测成功（gate/mihomo/审计全部绕过）

- **编号**: 020
- **严重度**: S2（安全语义破坏：拓扑强制被 guest 内进程一键撤销——正是 cage 威胁模型的核心场景"guest 内 agent 失控"）
- **攻击面**: R3 → 0.3 拓扑强制（4ab3c19）+ D/E（逃逸面）
- **发现时间**: 2026-11-19T06:50:00Z
- **发现者会话**: r3-s01
- **状态**: 待修复

## 复现（必须）

实测环境：临时 profile `/tmp/p1`（config 默认）→ `creance setup && creance up`（实例 `p1-downloads-e43c3d0f`，vz，Ubuntu cloud image）。以下全部在 guest 内执行（`creance shell -- sh -c '…'`）：

```sh
# ① guest 身份与 sudo 权限
id
# uid=501(shenyiyu) gid=1000(shenyiyu) groups=1000(shenyiyu),9(?) — lima 默认宿主同名用户
sudo -n true && echo SUDO-OK        # 无密码 sudo 成立

# ② 防火墙当前生效
sudo -n iptables -S OUTPUT
# -P OUTPUT DROP + lo/ESTABLISHED/DHCP/ICMP 四条 ACCEPT ✓

# ③ 撤防前直连（拓扑强制生效的证据）
timeout 5 curl -s -o /dev/null -w "%{http_code}" --connect-timeout 4 https://1.1.1.1
# 000 BLOCKED (correct)

# ④ 一条命令撤销（无密码）
sudo -n iptables -P OUTPUT ACCEPT && sudo -n iptables -F OUTPUT

# ⑤ 撤防后直连（逃逸完成）
timeout 8 curl -s -o /dev/null -w "%{http_code}" --connect-timeout 6 https://1.1.1.1
# http_code=301   ← 真实 HTTPS 到达 Cloudflare，完全绕过 mihomo/gate/审计

# ⑥ escape-test 如实翻转（探针有效，强制层失效）
# PROBE net-direct-egress ESCAPE / PROBE net-dns-external ESCAPE
```

- **期望**: 0.3 的声明——"direct egress is physically dropped, not merely discouraged"、guest 唯一出口是 ssh -R 隧道。该强制应对 guest 内**非 root 进程**成立；对 guest root/lifted 进程，拓扑设计文档（RELEASES/README）未声明豁免。
- **实际**: lima 默认 guest 用户（宿主同名，admin 组）持 **passwordless sudo**（lima/cloud-init 默认）；provision 以 root 设置 iptables 后未做任何事阻止该用户改回。guest 内失控 agent 一条命令即恢复全部直连能力，且**无需知道任何凭据**。`iptables-save` 的持久化同样可被覆盖。

## 根因猜测

`crates/creance-vm/src/lima.rs` generate_lima_yaml：**没有 `user:`/`groups:`/`sudoers` 定制**——lima 默认创建宿主同名用户 + admin 组 + NOPASSWD。provision（mode: system，root）设完防火墙后，主用户仍是"准 root"。

修复方向（供参考，非结论）：
1. lima.yaml 显式定义用户：`user: {name: <generated>, groups: [sudo 以外的普通组], sudo: false}`——0.4 的 guestprofile.username 字段**本来就是为此准备的，但没有接线**（见 R3 记档：generate_lima_yaml 不创建用户，guest 实际身份是宿主用户名镜像——tunnel.rs `User=$USER` 同样镜像）。接线 + `sudo: false` 一步到位。
2. 或保留 sudo 但锁 iptables：provision 末尾用 capability/owner 限制（`setcap` 移除、iptables 二进制 0700 root）——弱于方案 1（root 仍可改）。
3. 防火墙规则加 `iptables -A OUTPUT -m owner --uid-owner <root-only>` 类的保护不可行（规则本身可删）——**真正的强制必须去掉 guest 内的 root 获取路径**。

## 未验证想法

- guest 内普通用户（非 admin）是否存在于该镜像（lima 默认只有一个主用户）。
- vz/rosetta 特性下 provision root 脚本是否可被 guest 用户通过 lima guestagent 通道重触发（lima guestagent 以 root 跑，guest→agent 通道的暴露面）。
- `sudo` 完全移除后 provision 自身与用户日常操作的兼容性（apt 等由 provision root 完成，用户态 workload 不需要 sudo——需要确认 workload 是否假设 root）。

## 实测清理状态

`/tmp/p1` 实例防火墙处于**已撤防**状态（OUTPUT ACCEPT），会话收尾执行 `creance stop` 停机并删除临时 profile；宿主侧无残留影响（隧道宿主端只听 loopback）。
