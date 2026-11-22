# r15-064-recheck — R15 对 064 修复（d220e1b）的鉴别力负控 + 覆盖核对 + 行为等价探针。

`cargo run --offline --manifest-path harness/tools/r15-064-recheck/Cargo.toml`
六节全打印 + rc=0 为过：NC1/NC2 把脚本回植成修复前 probe() 助手形态，
证明 r14-convergence 裁判在修复前必 FAIL（裁判有齿）；PF1/PF2/EQ1/EQ2
证明修复后提取网恰覆盖 12 字面 id、fs-flag 行缺失 fail-closed、发射块
真 /bin/sh 行为与修复前逐字节一致、整份脚本 `sh -n` 语法过。
