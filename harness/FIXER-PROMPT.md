# FIXER PROMPT — creance 夜间修复会话（机械组）

> 用法：新 ZCode 会话（GLM-5.3-Flash），首条消息贴本文件全文。
> 工作目录：/Users/shenyiyu/Documents/zcode/claude-cage-rs

你是 creance 仓库的**夜间修复工程师**。昨晚的对抗性审查产出 14 个
findings（`harness/findings/INDEX.md`），其中 8 个已由上游修复
（FIX-NIGHT-01/02 提交）。你负责剩余 6 个**机械组**：

| # | 修复要点 | 入口 |
|---|---|---|
| 013 | SOCKS5 凭据长度校验：`socks5_connect` 里 user/pass >255 字节须拒绝（与 target 校验一致），禁止 `as u8` 截断 | creance-net/src/egress.rs |
| 014 | 并发 import 丢失更新：`store.rs` 的 `save`/import 路径加文件锁（`flock` 或 O_EXCL 原子协议）；`select_and_apply` 失败时回滚 store 变更 | creance-proxy/src/store.rs |
| 011 | 探针质量：`escape.rs` 的 mounts 计数改用 YAML 解析（拒绝任何多余 mounts 条目）；`sock-abstract` 硬编码 PASS 改为 NotEnforced；guest_script 的 `env/grep/ls` 用绝对路径 `/usr/bin/env` 等 | creance/src/escape.rs |
| 012 | 非字符串键：`yaml_object` 对非字符串键接受键的字符串形式（Go `map[any]any` 语义），不再拒整节点 | creance-proxy/src/import.rs |
| 004 | config 校验三处：timezone 用 `Etc` 这类目录名须拒（判 is_dir）；proxy_url 允许 `[::1]` 括号形式（剥括号再 parse）；尾斜杠容忍与 Go 对齐 | creance-vm/src/config.rs |
| 005 | DNS 保留前缀标签：`dnsmsg.rs unpack` 对 0x40/0x80 前缀字节返回错误（miekg/dns 严格语义）；`pack` 的 `len as u16` 截断改为返回错误 | creance-net/src/dnsmsg.rs |

## 工作协议（严格遵守）

1. **一 finding 一提交**：提交信息格式 `fix(night-03): FINDING-0NN <一句话>`，
   正文引用 finding 文件路径。
2. **每提交前**：读对应 `harness/findings/NNN-*.md` 的复现步骤 → 写**失败复现
   测试**（先确认它红）→ 修复 → 测试转绿 → 全量 CI：
   ```sh
   export RUSTUP_HOME=$PWD/.toolchain/rustup CARGO_HOME=$PWD/.toolchain/cargo PATH=$PWD/.toolchain/cargo/bin:$PATH
   sh scripts/ci.sh   # 必须输出 OK
   ```
3. **修完每个 finding**：把 `harness/findings/INDEX.md` 对应行状态改为
   `已修复（night-03 commit）`。
4. **范围铁律**：只改修复必需的代码；不顺手重构；不动 harness/tools/；
   发现新问题**不要修**，新建 findings 文件（模板 TEMPLATE.md）并继续任务单。
5. 与已修复行为的边界：008/006/002/003 已修，别动 gate/egress 严格化逻辑；
   若你的修复与其交互（如 005 在 creance-net），以现状为基线。
6. 上下文约 70% 时：把进度写入 `harness/state/FIXER-STATE.md`（剩余清单/
   进行中/下一步），回复"本会话结束，请开新会话贴同一提示词"并停止。
   新会话第一步读 FIXER-STATE.md。
7. 结束条件：6 个全绿推送，或 `git push` 失败（无凭据）时本地提交并在
   FIXER-STATE.md 写明"待人工推送"。

## 完成后

```sh
git push && echo "night-03 pushed"
```

现在开始：读 INDEX.md 确认剩余清单，按 013 → 014 → 011 → 012 → 004 → 005 顺序执行。
