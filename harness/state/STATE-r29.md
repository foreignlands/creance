# STATE-r29 — 第十三次收敛判词轮（v0.6.21 `e9ff8ff`）

**判词：不收敛。** 新发现 7 条（104–110，均 S5：守护/测试强度不足，只有改代码才能触发，没有运行时可达的路径）。审查循环继续。

## 基线与实机

| 项 | 结果 | 证据 |
|---|---|---|
| `sh scripts/ci.sh`（真实 RC，未经管道） | RC=0，186 passed / 0 failed，release 构建成功 | tools/r29-baseline/ |
| FRESH 腿（铁律 4）：全新 `$LAB`→init→setup→up→stop→up | init 0 / setup 0（23s）/ up1 0（52s）/ stop1 0 / up2 0（17s） | tools/r29-real-up/evidence/ |
| sealed 路径实装 | marker `ok`；up2 `-netdev user,…,restrict=on`；guest `/run/egress-armed`，OUTPUT DROP + 规范允许集 | up2-netdev.txt、facts-up2.log |
| escape-test（restrict=on） | 探针集与 R28 逐行 diff 为空；proxy-path ESCAPE 原因同前（lab 无代理节点），RC=1 不算回归 | evidence/escape2.log |

## 098–103 复核（每个核验点一行）

| 核验点 | 结论 | 用例 |
|---|---|---|
| F-099/100 私有字段：第二个字面构造点 | 已封（计数钉红） | NC-SEALcnt 红 |
| F-099/100 `derive(Default)` 铸令牌 | **绿 → F-105** | NC-GPdefault |
| F-099/100 `Self { _sealed }` 改名构造 | **绿 → F-105** | NC-GPself |
| F-099/100 transmute（无 allow） | 已封（workspace `unsafe_code = "deny"`） | NC-XMUTE 编译红 |
| F-099/100 transmute + `#[allow(unsafe_code)]` | **绿 → F-105**（lint 是 deny，不是 forbid） | NC-XMUTE2 |
| F-099/100 他 crate 用 pub `egress_verdict(字面量)` 铸令牌 | **绿 → F-105** | NC-XGATE |
| F-099/100 签名降级（`&Result<EgressVerified,_>`，判定前先武装） | **绿 → F-105** | NC-SIGres |
| F-099/100 vm.rs macOS/非 macOS cfg 对调 → Linux 变 noop | **绿 → F-106** | NC-VMcfgswap |
| F-099/100 qemu 后端路径实参对调 | **绿 → F-106** | NC-QMswap |
| F-099/100 verify_and_mark 让 verdict 判字面量 | **绿 → F-104** | NC-GPforge |
| F-099/100 guest 跑 canned echo | **绿 → F-104** | NC-GPcanned |
| F-099/100 guest_script 失败时喂通过串 | **绿 → F-104** | NC-GPerr |
| F-099/100 `.map` 改写探针结果 | **绿 → F-104** | NC-GPmap |
| F-099/100 `let out` 遮蔽 | 无引用形态被 unused_variables 拦；if 表达式形态**绿 → F-104** | NC-GPshadow 红 / NC-GPshadow2 绿 |
| F-099/100 main.rs 第二条 verify 路径 / 自写 marker | **绿 → F-107**（`std::fs::write` 写 provisioned） | NC-MAINfs |
| main.rs `match … Ok(wrote)`：Err 臂吞掉拒绝 | **绿 → F-107** | NC-UPerr |
| F-098 段内多出终止符形态的行 | 已封 | NC-HDws2 红 |
| F-098 段外 `if false; then … fi` 包裹 | **绿 → F-108**（CHANGELOG 的说法被证伪） | NC-HDiffalse |
| F-098 外层 `: <<'SKIPRULES'` 吞掉整段 | **绿 → F-108** | NC-HDnull |
| F-098 cat 行字面钉误伤 | 改用 `cat >/etc/…`（无空格）的合法写法会红：fmt 变体误伤，属可接受的严格度，不立案 | 静态 |
| F-098 临时目录清理失败 | 只影响测试卫生，不影响判定，不立案 | 静态 |
| F-101 enable 行注释掉 | **绿 → F-109** | NC-ENcomment |
| F-101 `cd` + 相对路径写第二个 unit | **绿 → F-109** | NC-UNITcd |
| F-101 `/etc/systemd/./system/` 写第二个 unit | **绿 → F-109** | NC-UNITdot |
| F-101 verbatim 允许集后追加 `-e` / `allowed.push` | **绿 → F-109**（钉实为 `contains`） | NC-ALLOWapp / NC-ALLOWpush |
| F-102 Checking 状态也计数 | 已封 | NC-WDopenC 红 |
| F-102 closed 分支 `tunnel::stop` 变死代码 | 已封（pidfile 真杀测试） | NC-WDcutdead 红 |
| F-102 阈值 10 tick（5s） | 已封（≤2.5s 行为测试） | NC-WDthr10 红 |
| F-102 阈值 4 tick（2.0s，保留 `>= 3` 字面） | **绿 → F-110** | NC-WDthr4c |
| F-102 两处 `= 0;` 复位被 `let _core_down_ticks = 0;` 遮蔽 | **绿 → F-110** | NC-WDshS / NC-WDshF |
| F-102 超时 `250.max(30s)` | **绿 → F-110** | NC-WDto |
| F-102 `rfind("\n#[cfg(test)]")` 切片 | 当前正确：gate.rs/gateprobe.rs/provision.rs 各只有一个行首 test mod，且都在文件尾 | 静态 |
| F-103 铁律 4 措辞 | 通过："必须"，并要求每批至少一条 `rm -rf → init → setup → up` 腿；本轮已执行 | OPERATOR-PROMPT |
| CHANGELOG [0.6.21] 在 tag 内；v0.6.20..v0.6.21 只有 `e9ff8ff` | 通过（19 个文件已逐一过）；条目中 "unforgeable"、"`if false` wrapping breaks the syntax"、"VERBATIM"、"both counter resets" 分别被 105/108/109/110 证伪 | git |
| escape.rs 搬空后的遗留 | 没有 re-export，也没有死代码（clippy -D warnings 绿）；剩余的 guest_script 是 escape-test 自用 | 静态 |

## 门禁矩阵与规程

- 34 个用例（`harness/tools/r29-negative-controls/cases.py`）。每个用例：`cp` 备份 → 锚点必须恰好命中 1 次 → needle 计数注入前后对比，证明注入已落地 → `cargo fmt` → `cargo test --workspace --locked` → 绿时再跑 `cargo clippy --all-targets -D warnings`，再跑 `check-probe-inventory.sh`（合起来等于 ci.sh 全部门禁腿）→ 还原，最后 md5 核对（每批 OK）。
- 正控：未变异 worktree 上 `cargo test` RC=0（logs/POS-wt.log），基线 ci.sh RC=0。
- 裁判双跑：25 个绿用例第二次独立运行结果一致（results-judge*.txt、logs-judge/）。
- 对照组（预期红，实际均红）：NC-SEALcnt、NC-HDws2、NC-WDopenC、NC-WDcutdead、NC-WDthr10、NC-XMUTE。
- 被 lint 拦下的形态（不计入发现）：NC-GPshadow（unused_variables）、NC-WDthr4/4b（clippy double_comparisons / manual_is_multiple_of），已换成 lint 干净的同义形态重跑。

## 没走通的路（诚实记录）

- unsafe transmute 不加 `#[allow]` 无法通过 CI。
- 当前三个文件的 `rfind` 切片都正确，多 test mod 只是假设场景。
- FRESH 腿和 sealed 路径在实机上行为正确；本轮所有发现都只能靠代码变更触发。
