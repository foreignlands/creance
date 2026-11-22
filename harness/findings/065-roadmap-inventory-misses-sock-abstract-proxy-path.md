# FINDING-065: ROADMAP 探针清单缺 sock-abstract 与 proxy-path——R14 对 F-063 "逐一对上"的裁定过宽

- **编号**: 065
- **严重度**: S5（文档一致性；探针本体在跑、缺行网 12/12 全覆盖经 r15 复核成立，安全语义不受影响）
- **攻击面**: E5 邻接（探针清单声明面）+ F-063 修复面验证记录修正
- **发现时间**: 2026-11-22
- **发现者会话**: night-auditor-v3（R15 收敛判词轮）
- **状态**: 待修复

## 复现（必须）

```sh
grep -n 'sock-abstract\|proxy-path' ROADMAP.md
# → 无命中（"已强制"与"待做"两节均无）
grep -n 'echo "PROBE sock-abstract\|echo "PROBE proxy-path' crates/creance/src/escape.rs
# → escape.rs:370（sock-abstract SKIP）与 escape.rs:406/408（proxy-path PASS/ESCAPE）
```

- **期望**: ROADMAP.md:38 标题即"escape 探针清单（研究A产出，逐步翻绿）"，
  且仓库自身把它当作同步目标——attack-surfaces E5 行"执行时同步：
  …ROADMAP 探针清单"、F-063 的完成标准即"清单与实际 id 全集对上"。
  清单（已强制 + 待做两节合计）应覆盖 guest_script 定义的全部探针 id。
- **实际**: 已强制列 guest 11 条（fs-flag-readable / guest-identity /
  guest-privilege / env-credentials / env-hex-tokens / ssh-material /
  sock-docker·lima-guestagent / net-direct-egress / net-dns-external /
  net-ipv6 / net-icmp-external），缺两个真实存在的 id：
  ①**proxy-path**——被强制的正向控制探针（出口链路唯一正向证据，
  ESCAPE 判死经 main.rs:407-411、缺行网经 064 修复后覆盖 12/12），
  QUICKSTART:85 明文承认它存在（"出口正向控制探针（proxy-path）需真实
  订阅节点"）；②**sock-abstract**——诚实 SKIP 的未实现层
  （escape.rs:368-370 注释明示），"已强制"不含它语义上说得通，但
  "待做"列表（大陆出口拒/AAAA 围栏/供应链探针/时区一致性）也没有它，
  逐步翻绿的路线图对这一已知缺口零跟踪。host 侧 6 id 与清单完全一致，
  无漂移。

## 根因猜测

F-063 修复（6155c1f）按其 finding 文本只做了两处最小同步（删
proxy-numeric-endpoint、补 net-icmp-external）；sock-abstract 与
proxy-path 自 ROADMAP 清单诞生起（6612b7f 首版）就缺席，0.6.4 加
net-icmp-external 与 night-15 清单重写两轮均未补。R14 对 F-063 的复核
把"与 escape.rs 实际 id 全集逐一对上"写进裁定（STATE-r14.md F-063 行）
时只单向核对了"清单提到的 id 在脚本中存在"，未做"实际 id 全集→清单"
的反向差集——验证记录过宽，本条同时是对该裁定的修正。病根与 063 自记
一致："声明面靠人肉同步，无 grep 门禁"；063 建议的 ci.sh 探针 id 门禁
至今未落地，同病第三次复发（058 改名脱节 → 063 死探针在列 → 065 活
探针缺席）。

## 未验证想法

- QUICKSTART:84-85 "guest 的身份/权限/网络类探针…均已强制"的类别枚举
  同样略过 fs/credentials/ssh/socket 类（README:74-75 有覆盖）——属
  概述句而非清单宣称，未单独立案，修 065 时可顺带对齐。

## 建议修复方向（供第二天的人参考，非结论）

- ROADMAP:38 已强制列表尾补 `proxy-path（正向控制，需真实订阅节点）`；
  待做列表补 `sock-abstract（unix abstract socket 滥用面，现如实 SKIP）`。
- 落地 063 就提过的 grep 门禁：探针 id 全集 = escape.rs 内
  `echo "PROBE <字面>` / host 侧 `id: "` 字面量集合，文档提及 id 必须
  是子集；若文档宣称清单完备则做双向差集。同病三复发，值得进 scripts/ci.sh。
