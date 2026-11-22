# FINDING-080: Lima 镜像 digest 钉死在会滚动的 `release/` URL 上——Ubuntu 下一次刷新云镜像后，每台 macOS 主机的 creance setup 都会因 digest 不符被 Lima 拒绝

- **编号**: 080
- **严重度**: S4（正确性/可用性：fail-closed，不破坏安全契约；但主目标平台 macOS 的 setup 定时失效，且必须发版才能恢复）
- **攻击面**: 供应链（a7ac0e3）/ D 层 Lima 供给
- **发现时间**: 2026-11-22T07:40Z
- **发现者会话**: r21-auditor（R21 第七次收敛判词轮）
- **状态**: 已修复（main-session，实机复验）

## 复现（必须）

```sh
# 1) 钉值与 URL
sed -n 14,36p crates/creance-vm/src/lima.rs
#   location = https://cloud-images.ubuntu.com/releases/24.04/release/ubuntu-24.04-server-cloudimg-arm64.img
#   digest   = sha256:50e24e1f…c50348e
# 2) release/ 是滚动指针：同一文件名在不同刷新批次里 sha256 不同
curl -fsSL https://cloud-images.ubuntu.com/releases/24.04/ | grep -o 'release-[0-9]*/' | sort -u | tail -8
curl -fsSL https://cloud-images.ubuntu.com/releases/24.04/release/SHA256SUMS          | grep cloudimg-arm64.img
curl -fsSL https://cloud-images.ubuntu.com/releases/24.04/release-20261017/SHA256SUMS | grep cloudimg-arm64.img
curl -fsSL https://cloud-images.ubuntu.com/releases/24.04/release-20260926/SHA256SUMS | grep cloudimg-arm64.img
```

2026-11-22 实测：

```
release-20260705/ release-20260725/ release-20260801/ release-20260814/
release-20260826/ release-20260911/ release-20260926/ release-20261017/   # 约每 2-3 周刷新一次
release/            arm64 = 50e24e1fb79e…c50348e   （= 钉值，当前指向 release-20261017）
release-20261017/   arm64 = 50e24e1fb79e…c50348e
release-20260926/   arm64 = 1d6bffe64b84…5cefc55   （上一批次，同名文件 digest 不同）
```

- **期望**: 钉 digest 时 URL 也钉到不可变的批次目录（`releases/24.04/release-20261017/…`），或按 QEMU 后端的做法运行时取 SHA256SUMS 校验（image.rs:51-62）；二者择一，不能"滚动 URL + 固定 digest"。
- **实际**: lima.rs 用滚动的 `release/` URL 配固定 digest。下一次 Ubuntu 刷新（按过去 4 个月的节奏，距 20261017 已 36 天，随时可能发生）后，`release/` 下的文件换成新批次，digest 不再匹配。a7ac0e3 的提交注释自己写明 "Lima refuses a substituted download"——合法刷新同样会被当成替换拒绝，macOS 上新 setup / 重建（F-051 的 setup 重建路径，以及所有"请 creance setup 重建"的提示）全部失败，只能等 creance 发新版改钉值。
- QEMU 后端不受影响：它运行时从同一 `release/` 取 SHA256SUMS 校验（image.rs:51-62），刷新后自动跟随。

## 根因猜测

crates/creance-vm/src/lima.rs:23-36：`image` 由 `releases/{UBUNTU_RELEASE}/release/…` 拼出，`digest` 是 a7ac0e3 抄自当天 SHA256SUMS 的常量。两个来源的生命周期不同。

## 未验证想法

- 本机是 Linux，未装 limactl，没有实跑 Lima 对 digest 不符的报错；"拒绝"依据 Lima images[].digest 字段的设计用途与 a7ac0e3 提交注释。Lima 是否在单镜像 digest 失败时有回退，未测（images 列表只有一项，无可回退项）。

## 建议修复方向（供第二天的人参考，非结论）

URL 改为 `releases/24.04/release-20261017/ubuntu-24.04-server-cloudimg-arm64.img`（不可变批次目录，Ubuntu 长期保留），与 digest 一起作为成对常量维护；加一条单测断言 location 不含 `/release/` 滚动段且与 digest 同批。升级镜像时两者同改。
