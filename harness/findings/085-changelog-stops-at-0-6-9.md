# FINDING-085: CHANGELOG 停在 0.6.9——0.6.10–0.6.13 四个已打 tag 的版本（含 restrict=on、供应链钉值、wire 下沉、up 守门语义变更）零条目，与 RELEASES.md 的发版规程不符

- **编号**: 085
- **严重度**: S5（质量：声明面漂移，不影响运行时行为）
- **攻击面**: 声明面 / 发版规程
- **发现时间**: 2026-11-22T07:20Z
- **发现者会话**: r22-auditor（R22 第八次收敛判词轮）
- **状态**: 已修复（main-session，实机复验）

## 复现（必须）

```sh
grep -n '^## \[' CHANGELOG.md | head -3            # 首条 = [0.6.9]
git log --oneline v0.6.9..v0.6.13 -- CHANGELOG.md  # 空：四次发版都没碰 CHANGELOG
git tag | grep -E 'v0\.6\.1[0-3]'                  # v0.6.10 v0.6.11 v0.6.12 v0.6.13 均存在
sed -n 3,6p RELEASES.md                            # "...manual: bump [workspace.package].version, update CHANGELOG, git tag"
```

- **期望**: 每个 tag 有 CHANGELOG 条目（R16/R17 审过 0.6.7/0.6.8 的 release commit 均为 CHANGELOG+Cargo.lock+Cargo.toml）。
- **实际**: daece7f（v0.6.12）、903ea7b（v0.6.11）只改 Cargo.toml/Cargo.lock；a24b26b（v0.6.13）把版本号直接夹在修复 commit 里。用户可见的语义变化——QEMU 第二次启动起 slirp restrict=on、up 新增 fw-armed 拒绝原因、Lima 镜像改钉 release-20261017、node tarball sha256 校验——在 CHANGELOG 中均无记载。

## 根因猜测

发版流程从 0.6.10 起走 fix commit + 独立 chore(release) 的形态，chore(release) 模板未包含 CHANGELOG。

## 未验证想法

- 无。

## 建议修复方向（供第二天的人参考，非结论）

补 0.6.10–0.6.13 条目；把"Cargo.toml 版本 == CHANGELOG 首条版本"做成 scripts/ci.sh 的一条 grep 门禁。
