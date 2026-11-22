# FINDING-067: README 验收节仍把已删除的 numeric-proxy-endpoint 探针列在"已强制"清单里——三处声明面中唯一无删除注记、无门禁看守的残留假宣称（同病第五复发）

- **编号**: 067
- **严重度**: S5（声明面漂移：对已不存在的控制做存在性宣称；隔离语义本身不受影响——真实校验在 config.rs validate + store applied() 对账承担，E5 裁定已确认）
- **攻击面**: E5 邻接（探针声明面第三处：README——R16 记忆 #7 "三处声明面看守强度不等"的实测兑现）
- **发现时间**: 2026-11-22
- **发现者会话**: night-auditor-v4（R17 收敛判词轮）
- **状态**: 待修复

## 复现（必须）

```sh
# 零操作静态事实：v0.6.8 工作树上
grep -n 'numeric proxy endpoint' README.md
# → README.md:72: "credentials in child env, numeric proxy endpoint, workspace-only mounts,"
#   位于 "## Escape-test: the acceptance harness" 节的
#   "Enforced since 0.3/0.4/0.5: …" 现在时清单内（README:70-76），无任何删除注记
grep -c 'proxy-numeric-endpoint\|numeric' crates/creance/src/escape.rs   # 探针本体
# → escape.rs:82 仅剩删除注释，无任何发射/检查代码（2026-11-21 E5 裁定删除）
sh scripts/check-probe-inventory.sh   # 门禁对 README 零看守
# → "probe inventory: bidirectional diff empty (guest 12 code ids, host 6)"，RC=0
#   （假宣称在本轮正控实测中全程在场、门禁全程绿）
```

- **期望**: README 的 escape-test 节是三处探针类目声明面（ROADMAP/QUICKSTART/
  README）之一。探针 `proxy-numeric-endpoint` 已于 2026-11-21 按 E5 裁定
  删除（空探针、两 match 臂恒 Contained）：ROADMAP.md:53 有历史注记
  （"原 proxy-numeric-endpoint 是永久绿的空探针，2026-11-21 E5 裁定删除"
  且明示"不参与门禁"）、docs/QUICKSTART.md:90 有同文注记——README 作为
  第三处声明面应同样如实（删除注记或从清单摘除）。
- **实际**: README:70-76 的现在时宣称清单 "Enforced since 0.3/0.4/0.5:
  profile validity, no host credentials in child env, **numeric proxy
  endpoint**, workspace-only mounts, …" 仍含该探针，无删除注记；读者
  （以及依赖 README 做验收预期的下游审查者）会相信 escape-test 存在
  并强制该层。该句子 6612b7f（README 诞生）写入后从未被触碰：E5 删除日、
  night-15 README 边界节补充（6155c1f）、night-17 文档同步、night-18
  QUICKSTART socket 类修复四轮全部绕过它。R14 曾裁定"全仓残留
  proxy-numeric-endpoint 引用仅三处且均为有意历史记录"（STATE-r14:23）——
  该 sweep 按 id `proxy-numeric-endpoint` grep，README 用的是空格短语
  "numeric proxy endpoint"，恰好漏网；R16 记忆 #5 复查 README:70-75 时
  焦点是 socket 类在场与否，同样滑过。**本轮正控实测证明门禁对这一假
  宣称零感知**（假宣称全程在树、门禁 RC=0）。

## 根因猜测

README.md:70-76（8612b7f 引入后冻结）。病根与 058/063/065/066 完全同族
——"声明面靠人肉同步、无自动看守"——第五复发（058 改名脱节 → 063
ROADMAP 死探针在列 → 065 ROADMAP 活探针缺席 → 066 家族探针零看守 →
067 README 死探针假宣称），且首次落在第三处声明面上。看守强度差异
（R16 记忆 #7）实测排序：ROADMAP 块有门禁双向看守；QUICKSTART 无看守
但 065/066 两轮已人工对齐且注记齐全；README 无看守且**已经漂移**——
066 修复把 QUICKSTART 枚举补齐时，README 这一行仍无人看。065 修正过
R14 的"单向核对"验证记录；本条同样修正 R14 的"残留引用仅三处"记录
（第四处=README:72，因短语拼写变体漏网）。

## 未验证想法

- 附带（同段 incompleteness，随本条记档不单独立案，R15 概述句先例）：
  README:74-76 guest 枚举 "the network probes (direct egress, external
  DNS, IPv6 — all enforced live)" 漏 net-icmp-external（0.6.4 已强制）与
  proxy-path（已强制、需真实节点）——每项单看为真但枚举不完整，同段
  已有死亡宣称，修 067 时顺带对齐。
- 门禁方向 1/2 的字符类 `[a-z0-9-]*` 对大写 id 静默截断（066 已记档，
  本轮未再展开；README 漂移恰证明"非 ROADMAP 声明面零看守"不是纯
  理论边界而是已兑现的复发路径）。
- ci.sh 本身含门禁步骤一事无任何层看守（删 ci.sh:18 门禁照绿）——元
  递归总在某层见底，记档不立案（R16 同裁定先例）。
- 新家族守卫（section 4）是文本在场证人：NC6c 实证把发射改为死分支
  `if false; then echo "PROBE sock-$s ESCAPE"; fi`（行为已死、文本在场）
  门禁仍绿——守卫如实声称"emission site textually present"（头注自洽），
  但注释 "deleting the probe has to fail HERE" 对行为性删除略有超额
  承诺；与 066 修复方向②（assert contains）同限，唯一行为证人=实机
  探针。记档，不立案。

## 建议修复方向（供第二天的人参考，非结论）

- 方向①（1 行）：README:72 删 "numeric proxy endpoint, " 一词，句尾补
  半句与 QUICKSTART:90 同义的删除注记（保持三处声明面措辞一致）。
- 方向②（治本向，≥1 行但跨面）：给 README 的 "Enforced since" 清单同
  样上标记块 + 门禁块解析（check-probe-inventory.sh 扩一个 README 块）
  ——三处声明面看守强度不等的根治；成本高于一词修复，可入 backlog。
- 顺带（同段）：README:74-76 网络探针枚举补 icmp 与正向控制两项措辞。
