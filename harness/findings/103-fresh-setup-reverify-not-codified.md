# FINDING-103: F-096 教训“实机复验必须走 FRESH setup”未沉淀到规程/产品文档

- **编号**: 103
- **严重度**: S5（质量：流程/文档）
- **攻击面**: harness/OPERATOR-PROMPT.md、docs/、README.md
- **发现者会话**: r28-auditor
- **状态**: 已修复（main-session，实机复验）

## 复现

```sh
grep -rn -i "fresh\|全新\|实机" harness/OPERATOR-PROMPT.md docs/ README.md    # 无输出
```

F-096 的根因之一是 v0.6.18 的“实机复验”在已供给实例上做，没走 fresh setup，`EGRESSRULES: not found` 只在新 bootstrap 中暴露（STATE-r27、F-096）。v0.6.20 的 tag 只改 crates/ 与 harness findings/state；OPERATOR-PROMPT 的工作循环/铁律与 docs/ 均没有“实机复验 = fresh init+setup→up→stop→up”的条款，INDEX 096/097 状态栏写“实机复验”也不注明是否 fresh。

## 建议

OPERATOR-PROMPT 铁律加一条：涉及 bootstrap/供给面的修复，实机复验必须在新 LAB 目录 fresh `init`+`setup` 后跑 up1→stop→up2 全链，并在 STATE 中记录二进制 md5 与 LAB 新建证据（参考 harness/tools/r28-real-up/run.sh）。
