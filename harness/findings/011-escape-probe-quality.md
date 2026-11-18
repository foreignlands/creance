# FINDING-011: escape 探针质量缺陷合集 — mounts 计数三种 YAML 格式骗术、sock-abstract 硬编码 PASS、env-credentials 探针在非 Anthropic API_KEY 宿主上恒误报

- **编号**: 011
- **严重度**: S4（探针可被骗/说谎——削弱逃逸检测的信任基础，不直接破坏隔离）
- **攻击面**: E1 + E2（探针本身）
- **发现时间**: 2026-11-19T01:45:00Z
- **发现者会话**: s01
- **状态**: 待修复

## 复现（必须）

### 1. mounts-workspace-only 计数骗术（3 变体，YAML 全部合法）

`escape.rs:109-113` 用 `lines().filter(|l| l.trim_start().starts_with("- location:")).count() <= 1` 判定。以下 lima.yaml 写法全部是 lima/mihomo 级 YAML 解析器接受的合法形式，但计数为 0：

```yaml
# 变体 A：dash 后双空格（YAML 合法——dash 后 ≥1 空格即可）
mounts:
  -  location: /Users/me/secret
     mountPoint: /secret
# 变体 B：flow 形式（单行，无 "- location:" 行首）
mounts: [{location: /Users/me/secret, mountPoint: /secret}]
# 变体 C：折行（dash 单独一行）
mounts:
  -
    location: /Users/me/secret
```

探针输出 `Contained`，实际挂载了宿主敏感目录。lima 对这些格式的实际接受度（真实 limactl create）未验证——YAML 语法层面成立；探针的意图是**防篡改检测**，格式宽容即绕过。

### 2. sock-abstract 探针硬编码 PASS

`escape.rs:207`：`echo "PROBE sock-abstract PASS"` —— 无条件输出。同文件 `net-*` 三个探针用 `SKIP`（遵守 "never silently pass" 哲学），唯独 sock-abstract 用 PASS——**说谎**：它从未检查任何东西。

### 3. env-credentials 探针在常见宿主环境恒误报

`escape.rs:192`：`env | grep -qE 'ANTHROPIC_API_KEY|CLAUDE_CODE_OAUTH_TOKEN|_API_KEY='` —— grep 模式 `_API_KEY=` 匹配**任何**以 API_KEY 结尾的变量，而宿主剥离清单（`vm.rs:134-152` STRIPPED，与 Go main.go:537 一致的窄清单）只剥 ANTHROPIC_API_KEY/CLAUDE_CODE_OAUTH_TOKEN。宿主设置 `OPENAI_API_KEY`/`DEEPSEEK_API_KEY` 等常见变量时（会传给 limactl/guest），探针**必报 ESCAPE**——不是泄漏（两边共同设计），是探针与清单不一致的误报，让 escape 套件在该类宿主上失去判别力。

### 4. guest oracle 的外部命令可被 guest 内 PATH 污染欺骗

`env`/`grep`/`ls` 三个外部命令（`[ ]` 是 builtin）——若 guest 内存在恶意软件且能影响 hostagent 执行 shell 的 PATH 解析（sanitized_env 不管理 PATH），假的 `env`/`grep` 可让 env-credentials/ssh-material 探针报 PASS。

## 根因猜测

1. 字符串前缀匹配代替 YAML 解析（mounts 计数）。
2. sock-abstract 是占位实现却用了 PASS 而非 SKIP（违背同文件 NotEnforced 哲学，escape.rs:8-12 注释明确承诺"never silently pass"）。
3. 探针 grep 与 STRIPPED 清单演进不同步。
4. FINDING-010 使全部 FS/gate 探针读取的 lima.yaml 与真实实例脱节——修 010 前这些探针的输出本就与真相无关。

## 未验证想法

- lima 2.3 对变体 A/B/C 的实际接受度（需要真实 limactl create 验证；若 lima 拒绝则降为理论）。
- hostagent 执行 guest script 时的实际 PATH 继承链（limactl shell → guest ssh → guest 默认 shell PATH）。
- flag_path 参数在 cmd_escape_test 的来源（若来自用户输入则存在换行注入假 PROBE 行的面）。

## 建议修复方向（供第二天的人参考，非结论）

1. mounts 计数改为 serde_yaml 解析后取 `mounts` 数组长度（lima.yaml 结构固定，可反序列化）。
2. sock-abstract 改 `SKIP` 并注明缺失的检查（abstract unix socket 枚举）。
3. env-credentials 的 grep 模式与 STRIPPED 清单对齐（由清单生成）。
4. PATH 用绝对路径调用 `env`/`grep`/`ls`（/usr/bin/env 等）。
