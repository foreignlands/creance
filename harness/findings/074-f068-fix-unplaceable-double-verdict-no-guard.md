# FINDING-074: F-068 修复面三处残留——旗标不可落盘时空真 PASS 行照常输出、再追加 SKIP（同一探针两个判词，与提交信息"SKIP instead of vacuous PASS"不符）；删掉放置代码 CI 全绿（无行为守卫）；被打断的 escape-test 把 oracle 留在宿主

- **编号**: 074
- **严重度**: S5（输出/声明面不一致 + 缺守卫；退出码不受影响——消费方只认 " ESCAPE"，可放置路径下修复真有牙）
- **攻击面**: E2（guest_script oracle）/ F-068 修复面
- **发现时间**: 2026-11-22T06:07:08Z
- **发现者会话**: night-auditor-v6（R19 第五次收敛判词轮）
- **状态**: 待修复

## 复现（必须）

```sh
# 真实 release 二进制 + QEMU 后端夹具 + 伪 ssh（在宿主执行探针脚本 = 最大逃逸视角）
cargo build --release
sh harness/tools/r19-flag-skip/run.sh      # RC=0
```

- **期望**: 修复提交 a601c6a 自述 "unplaceable flag reports SKIP instead of vacuous PASS"——不可落盘时该探针只有一个判词 SKIP；放置逻辑受测试守卫（R18 STATE 下一轮建议 1："加单测断言运行时旗标存在"；R19 任务书"删放置代码→某层必红"）；跑后不留 oracle。
- **实际**:
  ```
  == A: flag placeable           PROBE fs-flag-readable ESCAPE   （修复有牙 ✓；跑后旗标已删 ✓）
  == B: flag unplaceable         PROBE fs-flag-readable PASS
                                 PROBE fs-flag-readable SKIP — oracle flag 未能落盘
  == C: transport hangs, killed  oracle left on host after interrupted run: yes (creance-escape-oracle)
  ```
  负控（R19，cp 备份/md5 还原）：把 main.rs 的 `std::fs::write(&flag, …).is_ok()` 换成 `true`（放置代码删除、SKIP 分支一并失效 → 回到 F-068 的空真 PASS）→ `cargo test -p creance` **RC=0**，5 个 test-result 块全 ok；门禁 check-probe-inventory.sh 只做 id 文本对账，同样看不见。

## 根因猜测

- `crates/creance/src/main.rs:364`（flag_placed）与 `:420-426`（SKIP 分支）：SKIP 行在 guest 输出逐行回显（:411-416）**之后**追加，guest 脚本照常对缺失旗标打印 PASS，主机侧没有抑制/改写该行。
- cmd_escape_test 在二进制 crate 内、无单测；放置/删除顺序无任何断言。
- 删除只在正常返回路径执行（:420），无 Drop 守卫/信号处理；guest_script 无时限（vm.rs:341-377 `wait_with_output`），传输挂起时用户 Ctrl-C 即遗留 `<environment_dir>.escape-flag`。

## 未验证想法

- 遗留旗标在下一次 escape-test 被覆写，无安全后果；若用户的 workspace 父目录同步到云盘，会多出一个可见文件。

## 建议修复方向（供第二天的人参考，非结论）

旗标不可落盘时不向 guest 发 fs 探针（或渲染时把 FLAG 置空令脚本直接打印 SKIP），保证单一判词；把"放置→运行→删除"抽成可单测的函数（或 RAII 守卫）并断言运行期旗标存在；r19-flag-skip 可作行为负控。
