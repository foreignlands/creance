# creance harness — 夜间自动化压测体系

让一个 LLM agent（当前：GLM 5.3 Flash，3 亿 token 夜间额度）对 creance
进行持续、对抗性的测试、检索与审查。第二天人工（或另一个会话）按
`findings/INDEX.md` 修复。

## 一分钟启动

把 [`OPERATOR-PROMPT.md`](OPERATOR-PROMPT.md) 全文作为首条消息发给
agent（ZCode 新会话 / 任何能跑 shell 的 agent CLI），工作目录指向本仓库。
它会自己读攻击面地图、自己循环、自己压缩上下文、自己记录发现。

## 目录

| 路径 | 作用 |
|---|---|
| `OPERATOR-PROMPT.md` | 审查员提示词（角色、循环、压缩、记录协议） |
| `attack-surfaces.md` | 攻击面地图：45 个测试方向 × 入口代码位置 |
| `findings/` | 发现记录（`NNN-slug.md`，索引在 `INDEX.md`） |
| `tools/` | agent 被允许创建的测试工具/复现脚本（唯一可写代码区） |
| `state/STATE.md` | 上下文压缩文件：跨会话续跑的单一事实源 |
| `run-loop.sh` | 可选的外层 shell 驱动（会话死亡自动重启） |
| `ESCAPE-BRIEF.md` | 模型驱动逃逸演练任务书（VM 内红队，需先接入模型 CLI） |

## 规则速览（详见 OPERATOR-PROMPT）

- 仓库代码**只读**；产出只进 `tools/` 与 `findings/`。
- 优先离线（复用回环测试基建）；在线测试仅走本地 mihomo direct 冒烟核。
- 每个发现必须可复现：命令 + 预期 + 实际。
- 上下文将满 → 写 `state/STATE.md` → 结束会话；新会话第一步读它。
