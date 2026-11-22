# FINDING-079: v0.6.12 新增面零行为守护——wire 严格 CL、workbench 拒 TE、node sha256 钉、Lima digest 钉，七例注入 cargo test 全绿；wire.rs 文档称 tunnel 读者共用、"每个读者一致拒绝"与 egress 实况不符

- **编号**: 079
- **严重度**: S5（质量：当前行为正确；与 F-076 同类——修复/新增面不可被 CI 守住）
- **攻击面**: A7/B3（98865d5 wire 下沉）+ 供应链（a7ac0e3）
- **发现时间**: 2026-11-22T07:40Z
- **发现者会话**: r21-auditor（R21 第七次收敛判词轮）
- **状态**: 已修复（main-session，实机复验）

## 复现（必须）

```sh
sh harness/tools/r21-negative-controls/run.sh   # B 节；证据 harness/tools/r21-negative-controls/evidence.log
```

v0.6.12 实测（每例 cp 备份 → perl 注入 → grep -c=1 → cargo test → cp 还原 → md5sum -c 全 OK）：

```
NC-CLd:  wire.rs:81  (None, Ok(n)) → (_, Ok(n))           重复 CL 被接受   -p creance-net -p creance-gate -p creance  test-RC=0
NC-CLx:  wire.rs:82  _ => return Err(..) → _ => {}         重复/非法 CL 全接受                                        test-RC=0
NC-TE:   serve.rs:77 "transfer-encoding" → "…X"            workbench 不再拒 TE                       -p creance       test-RC=0
NC-NODE: provision.rs x64 sha256 末位 c2→c3                 钉值错误                                  -p creance-vm    test-RC=0
NC-NOCK: provision.rs  if [ -n "$CREANCE_NODE_SHA256" ] → if false   校验整段跳过                    -p creance-vm    test-RC=0
NC-DIG:  lima.rs:35  digest 末位 e→f                                                                  -p creance-vm    test-RC=0
NC-DIG2: lima.rs:34  "digest" 键 → "digestX"（Lima 不认，等于不校验）                                -p creance-vm    test-RC=0
```

- **期望**: FINDING-006 的"拒重复/非法 CL"规则下沉到 creance-net::wire 后，至少一条测试在规则放宽时变红；供应链钉值（node tarball sha256、Lima 镜像 digest）被删/被改/被跳过时至少一条测试变红。
- **实际**: 七例全绿。wire.rs 的 tests 模块（:132-185）只测 read_header_block；新函数 parse_header_block / strict_content_length 零单测；gate.rs 与 serve.rs 的测试里没有任何双 CL / 非法 CL / TE 请求。sha256/digest 常量无断言（lima.rs tests 只断言 locale、/32 表等）。
- **文档漂移（同一 commit 引入）**：
  - wire.rs:55-58 称 parse_header_block "Shared by the gate, the workbench, and tunnel readers so the per-field iteration lives in exactly one place"——tunnel 读者（egress.rs:737 起的响应解析）并不调用它，egress.rs:782-819 仍有自己的逐字段迭代。
  - wire.rs:72-76 称重复 CL 是 "an ambiguity-smuggling vector every reader must refuse identically"——egress.rs:808-816 对**相同值**的重复 CL 是接受的（只拒不同值，"ambiguous Content-Length"）。两种规则各自可辩（请求侧 vs 响应侧、Go net/http 接受同值重复），但注释所称"一致"不成立。

## 根因猜测

98865d5 是纯重构（去重），按"行为不变"处理没有补测试；原 gate/serve 内联实现本身也无测试，下沉后守护缺口原样带入。a7ac0e3 新增的是数据常量 + shell 片段，现有测试只做子串存在性检查，未覆盖这两段。

## 未验证想法

- 无。

## 建议修复方向（供第二天的人参考，非结论）

wire.rs 加 strict_content_length 的表驱动单测（无 / 单个 / 同值重复 / 异值重复 / 非数字 / 负数 / 超 usize）；gate 与 serve 各加一条双 CL → 400、serve 加一条 TE → 400 的端到端断言；provision.rs 断言渲染脚本含两个 sha256 钉值与 `sha256sum -c`；lima.rs 断言 images[0].digest 存在且与常量一致。wire.rs 两处注释改为如实描述（只服务请求侧 gate/workbench；egress 响应侧规则见 egress.rs）。
