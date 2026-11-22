# STATE-r20 — 第六次收敛判词轮（v0.6.11 / 903ea7b）

**判词：不收敛。** 本轮新立案 2 项（076、077，均 S5）。按规则不发收敛判词。

- 审查分支：audit/r20（基于 main=v0.6.11，未改 crates/ scripts/ docs/）
- 任务书 ~/r20-auditor-prompt.md 不存在 → 按会话摘要 + harness/OPERATOR-PROMPT.md 执行
- 环境：Ubuntu，/dev/kvm，QEMU 6.2.0，cloud-init 26.1（Ubuntu 24.04 cloud image）

## 基线

`sh scripts/ci.sh` → **RC=0**（fmt / clippy / probe inventory / test / release build）。

## A. 修复复核（逐行）

| 项 | 结论 | 证据 |
|---|---|---|
| 073 per-backend /32 | **行为成立**。QEMU 渲染 rules.v4：/32 行 4、/24 行 0；规则在位时发往 192.168.5.77 / 10.0.2.77 的 UDP/67 与 ICMP 都被 guest 内核拒绝，宿主抓包 0 条 | tools/r20-slirp-restrict（R=0,P1） |
| 073 守护 | **无守护**。QEMU/Lima 主机表互换后 CI 仍绿 → 076 | tools/r20-negative-controls NC-073q/l |
| 074 单判词 | **行为成立**。旗标放不下时只出 1 行 SKIP；放得下时正控出 ESCAPE；跑完后旗标被删 | tools/r19-flag-skip A/B |
| 074 守护 | **无守护**。注入 PASS+SKIP 双判词或令 flag_placed 恒真，CI 都绿 → 076 | NC-074、NC-F |
| 074 中断残留 | 未修（R19 已记）：creance 在中途被终止时旗标留在宿主上。旗标内容无敏感信息，下次运行会覆盖，不立案 | r19-flag-skip C |
| 075 runcmd 调序 | **成立**。runcmd[0]=mount_script，runcmd[1]=bootstrap | qemu/provision.rs:46-60 |
| 075 up 挂载校验 | **成立**。实机 up#1 输出 mount-ok 后才写标记；宿主与 guest 双向读写 9p 正常 | r20-075-interrupt/evidence up1/et1 |
| 075 实机中断 | **fail-closed**。首启 modules:final 后 15s 对 qemu 发 SIGKILL（模拟断电）→ 再 up 两次都 RC=1 并报 "ssh 未在预算内就绪"，不会出现"挂载缺失但全绿"。根因：guest 页缓存未落盘，/etc/ssh/ssh_host_* 全是 0 字节（离线 nbd 检查），sshd 永远起不来，只能 setup 重建。这是硬断电造成的崩溃一致性问题，产品停机走 QMP powerdown，不立案，记为已测变体 | r20-075-interrupt/evidence |
| restrict：未供给首启 | **成立**。首启 netdev 不含 restrict（`user,id=net0,hostfwd=…`），中断后再启仍不含 | 实机 cmdline ×2 |
| restrict：供给后 | **成立（下次启动生效）**。up#1 写标记，同一 qemu 进程不变且无 restrict；stop→up#2 出现 `restrict=on,hostfwd=…`。当前会话不受保护 → 077 | 实机 cmdline |
| restrict 下 ssh hostfwd | **成立**。实机 up#2 RC=0；lab R=1 时 P0 正常 | up2.log、r20-restrict-1.log |
| restrict 下 ssh -R 反向隧道 | **成立**。实机通过 -R 访问宿主监听，HTTP 200；guest 直连 10.0.2.2 被拦；lab R=1 时 P3 也是 200 | 实机、r20-restrict-1.log |
| restrict 下 9p | **成立**。up#2 下 mountpoint 正常，能读首会话写的文件、能写新文件且宿主可见 | 实机 |
| restrict 第二道防线效力 | **成立**。lab 中 root 冲掉 iptables 后：R=0 时 TCP 1.1.1.1:443 OPEN，抓到发往外网的包；R=1 时全部被拦，抓包 0 条 | r20-restrict-0/1.log |
| restrict 下探针 | 两次 escape-test 的 12 行判词逐行一致；proxy-path ESCAPE 是因为 lab 没有代理节点，两种模式相同 | et1/et2 |
| 标记可否被 guest 伪造 | **不可，且无收益**。标记在宿主 state/qemu/<inst>/ 下，guest 唯一的共享面是 workspace（9p 只映射 workspace 路径，mapped-xattr 不会把符号链接落成宿主链接）。伪造标记只会让网络更严，不会更松 | 源码 + instance.json |
| 标记清理路径 | **成立**。setup 重建时整个实例目录被 remove_dir_all，标记消失（实机 present→absent）；stop 保留标记（预期）；挂载校验失败时不写标记，并停掉本次启动的 VM | r20-075.log、mod.rs:288-300 |
| 门禁矩阵 | **成立**。POS RC=0（guest 12 / host 6）；NC-A 1、NC-B 1、NC1 1、NC2 1、NC3 2、NC5 11、NC6v 1 条 FAIL，全部 RC=1；4 个文件 md5 还原 OK | tools/r20-gate-matrix/evidence.log |
| 裁判双跑 | r14/r15 原工具不能针对 v0.6.11 编译（guest_script 新增 bool 参数）。在 tools/r20-judges 补上 `true` 参数（等价旧语义）；两个裁判各跑两次，都 RC=0，输出 md5 一致（2ecbd0c1 / 965e444c） | tools/r20-judges/evidence |

## B. v0.6.10..v0.6.11 邻接面

- gate.rs / serve.rs：拒绝重复或非法 Content-Length；serve 拒绝 Transfer-Encoding；状态行加原因短语。gate 每个连接只处理一个请求（Connection: close），TE 没有走私面。无发现。
- serve.rs 删掉了 `live` 字段，但它只是 Arc 克隆，计数仍在 spawn 闭包里递减，行为不变。已知残余：handler panic 会泄漏连接槽，这是旧行为，本轮未构造出 panic 输入。
- store.rs：只有 NotFound 才新建 store，其他 IO 错误 fail-closed。成立。
- running.rs：instance_dir 守卫简化为 `file_name().is_none()`，逻辑等价。
- pidfile.rs：私有临时文件 + rename。成立。
- provision/escape/qemu：见 A 节。

## 新发现

| # | 严重度 | 一句话 |
|---|---|---|
| 076 | S5 | v0.6.11 三处修复面没有行为守护：五种注入（删 restrict、QEMU/Lima /32 互换、F-074 双判词回退、flag_placed 恒真）下 cargo test 全绿 |
| 077 | S5 | restrict=on 文档与实际不符（mod.rs:4-7、ROADMAP:11、runner.rs:372）；完成供给的那次会话始终没有第二道防线，也不提示用户 |

## R21 建议

1. 修 076：每个修复点补一条会变红的测试，用 tools/r20-negative-controls 复验，预期全部 RC≠0。
2. 修 077：同步文档；可选供给后自动重启或热替换 netdev，用实机 cmdline 复验。
3. R21 = 第七次收敛判词轮。
