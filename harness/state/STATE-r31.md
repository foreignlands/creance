# STATE-r31 — v0.6.23 (3cd02f6) 第十四次收敛判词轮（续）

## 判词：**不收敛**

本轮新立案 117–122（全部 S5，守护/测试强度不足，需代码变更才可触发，无运行时可达路径）。按任务书“有任何新发现 ⇒ 不收敛”，**不发收敛判词**，审查循环继续。

## 基线

`sh scripts/ci.sh > /tmp/r31-ci-baseline.log 2>&1; RC=$?` → **RC=0**（release build OK）。日志：`harness/tools/r31-baseline/ci.log`、`ci.rc`。
注：repo-local `.toolchain` 环境首跑失败（rustup 无 default toolchain，环境问题，日志 `ci-localtoolchain.log`），改用全局 stable 重跑得 RC=0。

## FRESH 实机腿（铁律 4）

`rm -rf $HOME/r31-lab → init RC=0 → setup RC=0 (21s) → up RC=0 (58s) → stop RC=0 → up RC=0 (18s)`，marker ok，`-netdev user,…,restrict=on`。`escape2 RC=1` 与 r29/r30 同值，非本轮回归：失败项为 `PROBE proxy-path ESCAPE`——该探针是正控（经 host core 的 socks5 唯一出路能连通），lab 未配真实上游订阅故不通，非逃逸。日志 `harness/tools/r31-real-up/run.log`、`evidence/`。

## 111–116 复核（逐点）

| 点 | 结论 |
|---|---|
| F-111 `vm::`==2 vs `use crate::vm::*` 裸调 | 未成通道（源码推断：裸调丢失 `vm::stop_vm(p, i)`/`vm::guest_script` 字面即红；未跑变异）；但字面保留改语义可绕 → 117 |
| F-111 `Ok(`==0/`"`==0 | `if let`/`matches!` 等无需字面量的等价形无收益；canned 移到 vm.rs `guest_script_ok` 前缀字面绕 → 117 |
| F-111 RefCell 记录绑定注入 stop | 是，绑定到 `verify_and_mark_with` 的注入闭包；外壳本身无行为测试 → 117 |
| F-111 stop 参序断言 | 拦 body 内 `stop(instance, profile)`（NC-GPstopswap 红）；外壳闭包形参 `\|i, p\|` 对调绿 → 117 |
| F-111 fake runner 脚本断言 | 仅 `egress-armed` 子串，注释即满足（NC-GPscript3 绿）→ 117 |
| F-112 行级 pub 禁 | 拦 `pub(super)`/`pub(crate) fn`（NC-VISmint/2 红）；fn-pointer const 导出绕（NC-VISfnptr 绿）→ 118 |
| F-112 `_sealed`/`transmute` 全域禁 | 词禁可换 `mem::zeroed`（vm.rs）；扫描表仅 4/18 prod 文件，qemu/image.rs 铸令牌绿 → 118 |
| F-112 verdict→mark 位置序 | 拦前置 mark；序比较不受长度影响，插大段注释不改变序（源码推断），无新通道 |
| F-113 首个 `Err(` 行 verbatim | 拦 `Err(e) if …` 守卫臂（NC-UPguard 红）；`Result::Err(e) if …` 绕 → 119 |
| F-113 六文件 crate 扫描 | 拦直写（NC-MAINxfile 红）；`use … instance_dir as idir` + `concat!` 绕 → 119 |
| F-113 serve.rs gate 例外 | 前缀判定仅放过 `gate_`/`gate_instance`，未发现变体通道（源码审读） |
| F-114 heredoc 跨度：未终止外层 | 拦（NC-HDnull2 红）；前导空格终止行（trim 比较）对 dash 不终止 → 120 |
| F-114 `exit`/`return` 行首禁 | 拦行首 exit（NC-HDexit 红）；`exec true`/`true && exit 0`/`false`(set -e) 绕 → 120（dash/bash 实测 NOT-REACHED，`harness/tools/r31-shell-semantics/`） |
| F-114 `inside_span` 真值表 | `li > opener && li <= terminator`：终止行算 span 内、opener 行算 span 外——与钉线（opener 本身是 cat 行）用法一致，无误判 |
| F-115 systemctl/egress-lock 行白名单 | 拦行首 `systemctl disable egress-lock`、`env systemctl … egress-lock`（NC-ENdisable/NC-ENenv 红）；`/bin/systemctl` + 引号拆分 unit 名绕 → 121 |
| F-115 动词禁 / `cat >`==3 | 不覆盖 `printf >`/`cp`/`install`：printf 写第二个 root unit 绿 → 121 |
| F-116 裸名==5 | 改名 `_v2`+注释凑数红（源码推断：阈值行 `if core_down_ticks >= 3 {` 与 `let mut core_down_ticks` 各==1 失配）；新增独立标志不改计数 → 122 |
| F-116 `grace` 禁 | 子串禁会误杀 `graceful`（当前生产无此词，仅潜在误伤）；改名 `warm` 即绕 → 122 |
| F-116 `from_millis(500)`==2 | 字面计数，`from_millis(500) + from_millis(300)` 改周期为 800ms 绿 → 122 |

## sealed-token 攻击面

**有新通道**：零 unsafe 的 `pub(crate) const VERDICT: fn(..) = egress_verdict;`（118），以及扫描表外文件/非 transmute 的 unsafe 铸造（118）。

## CHANGELOG 对账（v0.6.21..v0.6.23）

- 34b6efb = v0.6.22，`[0.6.22]` 条目在 tag 内；3cd02f6 = v0.6.23，`[0.6.23]` 条目在 tag 内（`git show v0.6.2x:CHANGELOG.md` 各 1 处）。
- `[0.6.23]` F-112 段写 `_sealed`/`transmute` “banned across every creance-vm prod file”，实现为硬编码 4 文件表——文档与实现不符（并入 118）。其余条目与 diff 一致（gate.rs/gateprobe.rs/provision.rs/qemu/mod.rs/vm.rs/main.rs、findings 104–116 回填、版本号 0.6.23）。

## 门禁矩阵

用例：新 19（含对照 NC-ENenv、NC-UNITprintf 预期红）+ r30 回归 52。GREEN 17（裁判双跑 17/17 复现，立案 117–122）；回归 52 全红，其中 NC-XGATE/XMUTE/XMUTE2 为预期编译红（E0603 private / unsafe lint）。每轮 md5 还原 OK。正控：未变异基线 CI RC=0。详见 `harness/tools/r31-negative-controls/`。

## 下一轮建议焦点

117–122 修复后复核；优先把文本钉换成执行式/类型系统守护（全目录 walk、脚本在 stub 根下真实执行、令牌构造器私有子模块）。
