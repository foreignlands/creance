# FINDING-070: harness 声明面计数/状态陈旧——README 与 harness/README 称攻击面地图"20 项/20 个测试方向"（实为 45 条），attack-surfaces H 节标题仍写"全部未覆盖"（H1-H7 已逐条覆盖）

- **编号**: 070
- **严重度**: S5（文档不一致；无运行时影响）
- **攻击面**: harness/ 自身文档声明面 + attack-surfaces 状态注记（R18 任务书焦点 B 第 2、3 项）
- **发现时间**: 2026-11-22T05:29:28Z
- **发现者会话**: night-auditor-v5（R18 第四次收敛判词轮）
- **状态**: 待修复

## 复现（必须）

```sh
grep -n '20 项' README.md                         # 65: …findings 记录、20 项 攻击面地图…
grep -n '20 个测试方向' harness/README.md          # 18: | attack-surfaces.md | 攻击面地图：20 个测试方向 × 入口代码位置 |
grep -c '^| [A-H][0-9]' harness/attack-surfaces.md # 45
grep -n '^## H\.' harness/attack-surfaces.md       # 78: ## H. Linux QEMU 后端（v0.6.0 新面，全部未覆盖——下轮夜间审计的主攻区）
grep -n '^| H[0-9]' harness/attack-surfaces.md | grep -c '已覆盖'   # 7（H1-H7 全部"已覆盖"，F-057..F-061 等在案）
grep -c '状态由审查员更新' harness/attack-surfaces.md               # 2（文件尾同一注记重复两次）
```

- **期望**: 计数与地图实况一致（或不写死数字）；节标题状态与条目状态一致。
- **实际**: 两处现在时计数"20"对 45 条实况（A-H 八节，G/H 两节是后加的）；H 节标题"全部未覆盖——下轮夜间审计的主攻区"与 H1-H7 七条"已覆盖（R13 …）"直接矛盾；文件尾状态注记重复。

## 根因猜测

README.md:65 / harness/README.md:18 写于 harness 初版（a03771e，A-F 时代），后续 G 节（Go 对照）与 H 节（v0.6.0 Linux）扩表时无人回写计数；attack-surfaces.md:78 标题写于 H 节新增时，R13 覆盖 H1-H7 时只更新了行状态列，未改标题；文件尾注记在某轮追加时重复。均属"声明面靠人肉同步"同族（R17 记忆 #1）。

## 未验证想法

无。

## 建议修复方向（供第二天的人参考，非结论）

README.md:65、harness/README.md:18 去掉写死的"20"（改"A–H 八类攻击面地图"或实际条数）。attack-surfaces.md 是审查员可写文件：R18 已在 H 节标题处加注记指向本条，标题措辞与重复尾注的清理留给下一位审查员（本轮只记录）。
