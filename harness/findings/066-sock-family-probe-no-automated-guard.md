# FINDING-066: 已强制的 sock-$s 家族探针（socket 暴露检测）在全部自动化层结构性不可见——删除该探针五个层全绿，ROADMAP "已强制" 宣称可被静默证伪

- **编号**: 066
- **严重度**: S5（门禁/声明面覆盖缺口；当前无漂移、内核侧 containment 不受影响——但 socket 暴露检测这一唯一强制探针类的"已强制"宣称没有任何自动化看守，未来重构删掉它 CI 不会红）
- **攻击面**: E5 邻接（探针清单声明面）+ night-17 修复面（065 门禁的方向 2 allowlist）
- **发现时间**: 2026-11-22
- **发现者会话**: night-auditor-v4（R16 收敛判词轮）
- **状态**: 待修复

## 复现（必须）

```sh
# 临时删除 sock-$s 探针（escape.rs:364-367：注释行 + for s in /var/run/docker.sock
# /run/docker.sock /var/run/lima-guestagent.sock 循环三行），然后：
sh scripts/check-probe-inventory.sh
# → 实际输出与正控逐字相同："probe inventory: bidirectional diff empty
#   (guest 12 code ids, host 6)"，RC=0（NC6a 实测）
cargo test --locked -p creance --lib guest_script
# → "test escape::tests::guest_script_is_posix_and_flags_every_probe ... ok"，
#   RC=0（NC6b 实测）
# 验完 git checkout -- crates/creance/src/escape.rs 还原
```

- **期望**: ROADMAP.md:43-46 把 sock-docker·lima-guestagent 列为 VM 内已强制
  探针（socket 暴露逃逸的唯一检测探针：guest 摸到 docker/lima-guestagent
  unix socket 即报 ESCAPE）；065 修复买入的双向差集门禁的契约（
  check-probe-inventory.sh 头注）是"every id claimed as enforced must
  exist in the code"——一个已强制探针被删除，至少应有一层自动化红。
- **实际**: 删除 sock-$s for-loop 后，**全部五层自动化零报警**：
  ① `scripts/check-probe-inventory.sh` 方向 1（代码→清单）：参数化发射点
  `echo "PROBE sock-$s` 被 `grep -v -- '-$'` 过滤（头注 line 11 自述"tokens
  ending in '-' are the sock-$s family"），guest_code 的 12 个 id 本就不含
  家族，删探针后差集仍空；方向 2（清单→代码）：家族 token 经 line 58
  `guest_families='sock-docker·lima-guestagent'` **无条件 allowlist 豁免**，
  该 allowlist 从不对任何代码工件核验——是恒真豁免；② escape.rs 的
  探针断言测试（escape.rs:742-768）只断言 sock-abstract SKIP/非 PASS
  （:764-767），对 sock-$s 发射行零断言；③ main.rs 缺行提取器显式排除
  参数化点（main.rs:385-386 注释自述）；④ r14-convergence 裁判 [A]
  expected 24 条不含家族行（R16 实跑输出核对）；⑤ r15-064-recheck PF1
  12 字面 id 同提取基准。对照：host 6 id 与其余 11 个 guest id 均有
  ≥2 层自动化看守（门禁双向 + 测试断言/裁判 [A]）。

## 根因猜测

sock-$s 的 id 在构造期不可静态枚举（运行时路径决定），064 修复因此只把
**可静态枚举**的 fs-flag-readable 改回字面发射；家族探针留在参数化形态，
于是自动落出门禁方向 1 的字面宇宙、方向 2 又被 allowlist 无条件豁免。
豁免本身在门禁头注（"(allowlisted parameterized families excepted)"）与
ROADMAP 块外散文（"sock-docker·lima-guestagent 是参数化 sock-$s 的三
运行时家族名"）都有声明——**门禁没有违反它自己写下的契约**；缺口在于：
该豁免的后果（家族宣称零自动化看守、删除即静默证伪三处文档的"已强制"）
在任何文档里都未被陈述，且无任何其他层补偿。病根与 058/063/065 同类——
"声明面靠人肉同步、无自动看守"——但这次病灶活在为终结该病而买的门禁
自身的豁免条款里，属同病第四个复发向量（058 改名脱节 → 063 死探针在列
→ 065 活探针缺席 → 066 已强制家族零看守）。

## 未验证想法

- 附带（同族轻微项，随本条一并跟踪，不单独立案）：docs/QUICKSTART.md:84-88
  的类别枚举在 night-17 "顺带对齐"后仍略过 socket 类（065 未验证想法列的
  fs/credentials/ssh/socket 四类修了三类）——README:70-75 有 "socket
  exposure" 全覆盖、ROADMAP 已强制块有家族 token 且被门禁看守，QUICKSTART
  是概述句非清单宣称（R15 裁定不立案），但与 066 合并看时该句对强制面
  的枚举少了唯一未受自动化看守的探针类。
- 门禁方向 1 的 `[a-z0-9-]*` 字符类对含大写字母的 id 会静默截断（截断成
  空或短 token）——当前无大写 id，纯未来边界，随本条记档不展开。
- 家族 token 自身的外延漂移（如未来 sock-$s 循环加第 4 条路径而 ROADMAP
  仍写"三运行时"）同样不可自动检测——属同一豁免的另一面。

## 建议修复方向（供第二天的人参考，非结论）

- 方向①（≤2 行，与门禁现有风格一致）：方向 2 对家族 token 不再恒真豁免，
  改为核验参数化发射点字面在场——单独一行
  `grep -q 'echo "PROBE sock-\$s ESCAPE"' crates/creance/src/escape.rs || FAIL`，
  把家族从无条件 allowlist 改为显式守卫（escape.rs:365 的 for-loop 文本
  在源文件恒在，可静态 grep）。
- 方向②（1 行测试断言）：escape.rs:758 附近补
  `assert!(script.contains("PROBE sock-$s ESCAPE"))`——脚本文本是静态的，
  for-loop 在渲染产物中恒在，断言成立且让删除探针时 cargo test 红。
- 方向③（裁判侧）：r14-convergence [A] expected 集合补家族行（按
  sock-$s 字面形态）——但裁判只在审查轮人肉触发，①/②（CI 内）优先。
- 三方向任一即可闭 066 主项；QUICKSTART socket 类枚举补词（顺带）即闭
  附带项。
