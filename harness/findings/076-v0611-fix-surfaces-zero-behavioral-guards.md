# FINDING-076: v0.6.11 三处修复面零行为守护——删掉 restrict=on、QEMU/Lima 的 /32 主机表互换（F-073 S2 形态复现）、F-074 双判词原样回退、flag_placed 恒真，五种注入下 cargo test 全绿

- **编号**: 076
- **严重度**: S5（质量：当前行为正确，见 STATE-r20 复核；但修复不可被 CI 守住，其中 NC-073q 是 F-073 S2 的同形回归，NC-074 是 F-074 立案时明确要求补而未补的守护）
- **攻击面**: H1 / F-073、F-074 修复面 + 1ca32c8 restrict=on
- **发现时间**: 2026-11-22T06:45Z
- **发现者会话**: r20-auditor（R20 第六次收敛判词轮）
- **状态**: 待修复

## 复现（必须）

```sh
sh harness/tools/r20-negative-controls/run.sh
# 每例：cp 备份 → perl 注入 → grep -c 证注入落地(=1) → cargo test --locked -p <crate> → cp 还原 → md5sum -c
```

实测（v0.6.11 / 903ea7b）：

```
NC-R:    inject-grep-c=1 crate=creance-vm test-RC=0 failed=0   # runner.rs:150 "restrict=on," → ""
NC-F:    inject-grep-c=1 crate=creance    test-RC=0 failed=0   # main.rs:360 flag_placed = true
NC-073q: inject-grep-c=1 crate=creance-vm test-RC=0 failed=0   # qemu/provision.rs:47 改传 Lima 的 192.168.5.2/.3
NC-073l: inject-grep-c=1 crate=creance-vm test-RC=0 failed=0   # lima.rs:48 改传 QEMU 的 10.0.2.2/.3
NC-074:  inject-grep-c=1 crate=creance    test-RC=0 failed=0   # escape.rs:323 else 分支恢复 PASS+SKIP 双判词
crates/... : OK ×5 (md5 还原)
```

- **期望**: 每个修复至少有一条测试在其被撤销/接错时变红（F-074 立案标题即"no-guard"，建议修复含"加行为守护"）。
- **实际**: 五例全绿。
  - NC-073q 的含义由实机量化：`harness/tools/r20-slirp-restrict`（R20_RESTRICT=0, P2）显示 QEMU slirp 会把发往 192.168.5.77 的包路由出宿主——QEMU 规则若被换成 Lima 的 /32，即在 slirp 上为 192.168.5.2/.3 两个外部主机重开 UDP/67+ICMP 出口，回到 F-073 的 S2 形态，CI 无感。
  - NC-R：整个第二道防线可被一行删除且无测试察觉；runner.rs 的单测（:372 附近）只断言 hostfwd 形态，从不构造带 `provisioned` 标记的实例。
  - NC-074：escape.rs 唯一的 guest_script 单测（:769）只覆盖 `oracle_ready=true`；false 分支（F-074 修复本体）无断言。

## 根因猜测

- provision.rs 单测直接以字面量 `&["10.0.2.2","10.0.2.3"]` 调 `guest_bootstrap`，不经过各后端调用点（qemu/provision.rs:47、lima.rs:48），后端 → 主机表的绑定无断言。
- runner.rs `build_args` 的 `provisioned` 分支无单测；`provisioned` 取自磁盘文件（runner.rs 内 `Path::new(&paths::join(dir,"provisioned")).is_file()`），测试未造该文件。
- escape.rs tests 未调用 `guest_script(_, false, ..)`。

## 未验证想法

- 无。

## 建议修复方向（供第二天的人参考，非结论）

qemu/provision.rs 与 lima.rs 各加一条对渲染后 user-data 的断言（含本后端 /32、不含对端 /32）；runner.rs 加 tempdir 造 `provisioned` 前后两次 build_args 的断言；escape.rs 加 `oracle_ready=false` → fs-flag-readable 恰 1 行且为 SKIP 的断言；main.rs 的 flag_placed 计算可抽成小函数以便测。
