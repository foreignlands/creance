# STATE-r30 — v0.6.22 (34b6efb) 第十四次收敛判词轮

## 判词：**不收敛**

本轮新立案 111–116（全部 S5，守护/测试强度不足，无运行时可达路径）。按任务书“有任何新发现 ⇒ 不收敛”，不发收敛判词，审查循环继续。

## 基线

`sh scripts/ci.sh > /tmp/r30-ci-baseline.log 2>&1; RC=$?` → **RC=0**（187 passed / 0 failed；release build OK）。日志：`harness/tools/r30-baseline/ci.log`、`ci.rc`。
注：按 OPERATOR-PROMPT 的 repo-local `.toolchain` 环境首次运行 RC≠0（rustup 无 default toolchain，环境问题，非产品问题），改用全局 stable 重跑得 RC=0。

## FRESH 实机腿（铁律 4）

`rm -rf $HOME/r30-lab → init RC=0 → setup RC=0 (26s) → up RC=0 (57s) → stop RC=0 → up RC=0`，marker ok，`-netdev user,…,restrict=on`。`escape2 RC=1` 与 r29 同（r29 run.log 同值），非本轮回归。日志 `harness/tools/r30-real-up/run.log`。

## 104–110 复核（逐点）

| 点 | 结论 |
|---|---|
| F-104 `let mut out`+改写 | 拦（`let out`==1 计数+NC-GPshadow2 红） |
| F-104 stopped RefCell | 覆盖“拒绝时 stop 调用一次”，但 fake stop 忽略实参 → 111 |
| F-104 `stop(`==2 共享调用 | 计数不钉实参，`stop(instance, profile)` 绿 → 111 |
| F-104 F/S → `impl Fn` | 语义等价，非绕过（行为测试照跑）；但 prod 外壳 `verify_and_mark` 的 runner/stop 无钉 → 111 |
| F-104 Ok 臂条件化 | 绕过（NC-GPtmpgate 绿）→ 111 |
| F-105 `pub(super)`/`pub(crate)` | 绕过（NC-VISmint/VISmint2 绿）→ 112 |
| F-105 `use … as`/type 别名 | 无新通道（类型系统保证同一类型） |
| F-105 `mark_provisioned(` 位置序 | 不钉，可前置到 verdict 前 → 112；vm.rs transmute 铸令牌绿 → 112 |
| F-106 等价 cfg | 拦（NC-VMcfgcmt 红：真实路径写 marker 行为测试） |
| F-106 行为测试走 QEMU 路径 | 是（`qemu::instance_dir` 下 `provisioned` 断言） |
| F-107 600 字节窗 | 撑爆窗即红（fail-closed）；但注释/守卫臂内保留字面绿 → 113 |
| F-107 `instance_dir(&profile` | main.rs 内换形红（NC-MAINfs2）；lib.rs 写 marker 绿 → 113 |
| F-108 heredoc 内未闭合引号 | `sh -n` 拦 |
| F-108 `: <<X` 包裹 / 切片边界 | 绕过（NC-HDnull2、NC-HDexit 绿）→ 114 |
| F-109 Tab/双空格 `cat`、`cd` 变体、enable 撤销、变量拼路径 | 绕过（NC-UNITvar/UNITcd2/ENdisable/ENheredoc 绿）→ 115 |
| F-110 `3 <= ticks` 逆写 / 改名 | 拦（阈值行 trim 相等+声明计数） |
| F-110 阈值/周期等价放宽 | 绕过（NC-WDgrace/WDsleep 绿）→ 116 |
| F-110 1.3s 下界抖动 | 稳定：负载 3.5 下 15/15（`tools/r30-watchdog-jitter/result.txt`） |
| CHANGELOG [0.6.22] 在 tag 内 | 是；v0.6.21..v0.6.22 单 commit 34b6efb，17 文件与条目对账一致（“creance crate 禁 provisioned 字面”实为仅 main.rs → 113） |

## 门禁矩阵

52 用例：新 21 + r29 回归 30（NC-GPerr、NC-WDthr10/4c 锚点适配）+ NC-VMcfgcmt。GREEN 20（全部裁判双跑复现 20/20，立案 111–116），其余红或预期编译失败（NC-XMUTE/XMUTE2）。每轮 md5 还原 OK。详见 `harness/tools/r30-negative-controls/`。

## 邻接面

- escape.rs（859 行）：搬空后仅剩 `host_probes`/`guest_script`/`report` 三个 pub fn，无 gateprobe re-export、无 `allow(dead_code)`；未发现新通道。
- main.rs `Ok(wrote)`：`wrote` 只影响提示文案，`Ok(false)`（已武装/macOS）仍正确继续；可绕面见 113。
- 递归 walk：排除仅末尾 `#[cfg(test)]`，`#![cfg`/`#[path` 全禁，`tests::` 禁调；但只数 marker 名不数令牌铸造 → 112。

## 没找到的路

`Clone`/`Default`/第二构造点、他 crate 铸令牌、`&Result` 签名、dispatch cfg 对调/等价 cfg、qemu 实参对调、main.rs 内自写 marker、`if false` 包裹、允许集追加、watchdog 超时/遮蔽/逆写阈值 —— 均红。
