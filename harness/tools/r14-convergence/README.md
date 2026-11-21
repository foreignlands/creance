# r14-convergence — R14 收敛判词轮探针（v0.6.5 = 6155c1f）

两个互补证据件，都走**真实代码**（假核心/逻辑镜像的取舍见各自头部注释）：

1. **ere-matrix.sh** — F-056 转义表的全元字符引擎矩阵。R13.5 只实机测过
   `+`、`(`、a+b/aab 四场景；本探针把 14 个 POSIX ERE 元字符 + 对照组
   （plain/dz/d-）+ 交叉匹配守卫（`d.`/`d*`/`d?` vs `dx`）全部过一遍真
   `creance proxy-stop`（reap_orphan_cores）。平台边界：macOS/BSD regex；
   Linux glibc 对 `\]` 等转义的接受度留 Ubuntu 回填。
   用法：`bash ere-matrix.sh`；期望 `batches passed: 4/4`。
   批内 ≤5 个假核心并发（协议 ≤10 进程）；假核心为自守护化版
   （fakecore.c fork 即退）——首版用 bash `( cmd & )` 快速连发时踩到
   位置依赖的 fork/exec 竞态（后发进程整段不执行、pid 文件假缺失，
   曾产出成片假 CROSSKILL 报告），自守护化后消除。

2. **src/main.rs（cargo run --offline）** — F-062 修复面复核：
   用真 `creance::escape::guest_script()` 渲染产物 + 逐字符镜像
   main.rs（6155c1f）的两段消费逻辑——escape-test 的缺行提取器
   （[A]/[B]/[C]/[D]/[F] 节）与 up 防火墙守门真值表（[G] 节 10 行）。
   [E] 节原为 finding 064 的实证观测（fs-flag-readable 经 probe() 助手
   参数化发射、不在缺行网内、可被单独致盲）——**night-16 修复后 [A]/[E]
   已翻为修复后断言**：fs-flag-readable 必须在网内、其行缺失必须触发
   missing；helper 调用形态回归即 FAIL。

path-dep 指向本 checkout 的 crates/（tools/README #10 的已知状态：绝对
路径，别处 checkout 需改指）。发现记录见 `../findings/064-*.md`。
