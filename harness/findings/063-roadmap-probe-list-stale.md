# FINDING-063: ROADMAP.md 探针清单未随 E5 删除同步——仍宣称已删探针在"已强制"列表，且缺新增探针

- **编号**: 063
- **严重度**: S5
- **攻击面**: E5（probe-3 删除）执行清单的第三处（harness/attack-surfaces.md E5 行）
- **发现时间**: 2026-11-21 21:45 (+08:00)
- **发现者会话**: R13.5（night-auditor-v2，回归轮）
- **状态**: 待修复

## 复现（必须）

```sh
grep -n "proxy-numeric-endpoint\|net-icmp-external" ROADMAP.md
# → ROADMAP.md:16 已强制列表仍含 proxy-numeric-endpoint；
#   列表止于 net-direct-egress / net-dns-external / net-ipv6，无 net-icmp-external
grep -n "6 项探针" docs/QUICKSTART.md   # → QUICKSTART 已改对（宿主 6 项+四类 guest 网络探针）
```

- **期望**: attack-surfaces.md E5 行明确要求"执行时同步：escape.rs:81-97、
  **ROADMAP:16 探针清单**、README 计数"。night-14 只同步了 escape.rs 与
  QUICKSTART/README，ROADMAP 漏网——文档仍向消费者宣称一个不再存在的探针
  在"已强制"，同时漏掉 F-060 新增的 net-icmp-external（本机实机已 PASS）。
- **实际**: ROADMAP.md:16 陈旧（双方向都错：多列一个死探针、少列一个真探针）。

## 根因猜测

E5 是"删除+同步三处"的批量动作，night-14 的提交按 escape.rs→QUICKSTART→
README 推进，ROADMAP 没进提交清单（ROADMAP.md 不在 b62823c..afe9ec6 的
diff 里）。与 F-058 同类：改名/删改后无 grep 门禁，声明面靠人肉同步。

## 未验证想法

无（此条为纯文档一致性）。

## 建议修复方向（供第二天的人参考，非结论）

一行修复：ROADMAP.md:16 删 `proxy-numeric-endpoint`、在 VM 网络探针尾补
`net-icmp-external`。顺带可给 scripts/ci.sh 加一个 grep 门禁（探针 id 全集
= escape.rs 内 `PROBE <id>`/`id: "` 字面量集合，文档提及的 id 必须是子集）
——F-058+063 的病根是同一个。
