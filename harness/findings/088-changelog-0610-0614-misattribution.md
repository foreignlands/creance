# FINDING-088: CHANGELOG 0.6.10–0.6.14 与实际 commit/tag 不对账——v0.6.14 tag 内无 [0.6.14] 条目；[0.6.13] 把 v0.6.14 才落地的改动记在 0.6.13；[0.6.10]/[0.6.11] 各提前一个版本；两批 audit-batch 改动（含平台收缩）无任何条目

- **编号**: 088
- **严重度**: S5（质量：声明面漂移，不影响运行时行为）
- **攻击面**: 发版规程 / F-085 修复面
- **发现时间**: 2026-11-22T13:15Z
- **发现者会话**: r23-auditor（R23 第九次收敛判词轮）
- **状态**: 已修复（main-session，实机复验）

## 复现（必须）

```sh
git log --oneline v0.6.9..129782d -- . ':!harness'
for c in 5b47c6d 3783863 b144b77 911c202 1ca32c8 98865d5 a7ac0e3 23b0da2 a24b26b 1c55b30; do
  echo "$c $(git tag --contains $c --sort=v:refname | head -1)"; done
git tag --points-at 1c55b30; git tag --points-at 129782d
git show v0.6.14:CHANGELOG.md | grep -n '^## \['
sed -n 1,110p CHANGELOG.md
```

| commit | 首个包含它的 tag | CHANGELOG 记在 | 判定 |
|---|---|---|---|
| 5b47c6d idempotent up + DEFAULT_PORT | v0.6.11 | [0.6.10] 末条 | 提前一版 |
| 3783863 quality-audit 12 项（service 退出码、store 失败关闭、proxy-import 写 URL、qmp 超时、gate/serve CL/TE 失败关闭…） | v0.6.11 | 无 | 漏项 |
| b144b77 probe 判定语义定稿 + **平台收缩**（QEMU 仅 x86_64、Lima 仅 arm64、fetch-proxy-core 只留两资产）+ ssh 端口重分配 | v0.6.11 | 无 | 漏项（含用户可见的能力移除） |
| 98865d5 header 解析统一进 creance-net::wire | v0.6.12 | [0.6.11] | 提前一版；[0.6.12] 未提 |
| a7ac0e3 node sha256 + Lima digest 钉值 | v0.6.12 | [0.6.11] | 提前一版；[0.6.12] 未提 |
| 1c55b30 F-078/084 guest_script 内置 oracle、F-082/083 stamp、F-084 probe/verdict 下沉、workbench TE→400 socket 测试 | v0.6.14 | [0.6.13]（同时又记在 [0.6.14]） | 夸大 0.6.13 / 重复 |
| 129782d `[0.6.14]` 条目 | 无 tag（v0.6.14 指向 1c55b30） | — | v0.6.14 发布物里没有自己的条目 |

- **期望**: 每个版本条目只列该 tag 相对上一 tag 的改动；tag 内含本版本条目。
- **实际**: 见上表。[0.6.13] 条目由 1c55b30 回填时写入，混入了 v0.6.13（a24b26b）尚不存在的行为——R22 F-084 正是指出 a24b26b 缺 TE socket 测试、guest_script 仍收 oracle_ready 参数，而 [0.6.13] 声称两者已存在。

## 根因猜测

F-085 修复按"审查轮"而非"tag 区间"回填（条目标题即 night-NN/RNN audit round），且 [0.6.14] 在打 tag 之后单独提交。

## 建议修复方向（供第二天的人参考，非结论）

按 `git log vA..vB` 重排条目；补 3783863/b144b77；平台收缩单列 Removed；必要时 v0.6.14 重新打 tag 或在 0.6.15 说明。
