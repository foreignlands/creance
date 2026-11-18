# FINDING-001: 订阅 YAML 深嵌套触发 O(n²) CPU 消耗 — 1 MiB 恶意输入烧 406 秒，8 MiB 外推约 7 小时

- **编号**: 001
- **严重度**: S3（资源耗尽/DoS）
- **攻击面**: A1（订阅 YAML 炸弹）
- **发现时间**: 2026-11-18T15:43:46Z
- **发现者会话**: s01
- **状态**: 待修复

## 复现（必须）

```sh
# 生成 1 MiB 深嵌套 payload（512k 层，共 1048578 字节，恰在 8 MiB 限内）
python3 -c "print('proxies: ' + '['*524288 + ']'*524288)" > /tmp/deep.yaml
CREANCE_CONFIG=$(mktemp -d)/config.json \
  time target/release/creance proxy-import --name deep --file /tmp/deep.yaml
# 实测 406.6 秒后输出"无法读取 YAML……"（rc=1）

# 时间-输入曲线（黑盒，生产二进制 proxy-import）：
#   10k 层 (20 KB)   0.2s
#   50k 层 (100 KB)  3.6s
#   256k 层 (512 KB) 98.1s
#   512k 层 (1 MiB)  406.6s    ← 输入×2 → 时间×4，严格 O(n²)
# 外推 8 MiB（MAX_IMPORT 上限）≈ 26000s ≈ 7.2 小时单核 CPU。
```

- **期望**: 无论嵌套深度如何，解析耗时与输入大小成线性关系；或在入口做廉价深度预检（如线性扫描 flow 层数 >128 直接拒绝），最多毫秒级拒绝。
- **实际**: `serde_yaml::from_slice`（serde_yaml 0.9.34 / unsafe-libyaml 0.2.11）在拒绝前消耗 O(n²) 时间。1 MiB 输入 406.6s；远低于 8 MiB 上限即可让一次 import 挂死分钟~小时级。

## 根因猜测

`crates/creance-proxy/src/import.rs:40` 的 `serde_yaml::from_slice` 是入口。归因实验（`harness/tools/a1-yaml-bomb/src/bin/libyaml-probe.rs`）直接拉取 unsafe-libyaml 事件流（**不做** serde Value 构建）同样超线性：

```
1k 层   4ms      50k 层   3.47s
10k 层  162ms    100k 层  13.97s
                 200k 层  56.8s
```

且事件计数 = 2×depth+6（完整文档），证明 O(n²) 在 **unsafe-libyaml 0.2.11 的 scanner/parser**（对深层 flow sequence 的状态处理），而 serde_yaml 0.9 先全量生成事件缓冲再构建 Value —— 所以 Value 构建阶段的 128 层 recursion limit（"recursion limit exceeded at line 1 column 137"）虽然保证了**无栈溢出**，却不能阻止 libyaml 全量扫描的 CPU 成本。

**威胁模型成立**：订阅数据来自不受信 URL（`proxy-import --url`、workbench HTTP 导入 serve.rs:154、定时 refresh）。恶意/被劫持的订阅服务器返回 1 MiB 深嵌套 YAML：
- CLI 路径：主线程挂 7 小时级；
- workbench 路径：serve 64 槽位之一被占满 + 64 并发可放满 CPU（与 F2 慢速占槽协同）。

## 未验证想法

- 8 MiB 输入的精确耗时（未实测，仅外推——一次 7 小时的实验成本过高；1MiB 复测尝试因 CI 负载干扰被终止，原始 406.6s 为独占测量）。
- workbench 导入端点是否对请求体大小有独立上限（fetch.rs 对 URL 下载限 8 MiB；HTTP POST 上传路径未查）。
- 序列/映射之外的第三种深度载体（block scalar 内的 flow 集合）是否同样触发。
- mihomo 自身解析同样的 config.yaml 是否也 O(n²)（config 由 cage 生成、节点已经过限制，风险低）。

## 建议修复方向（供第二天的人参考，非结论）

在 `parse_nodes` 进入 `serde_yaml::from_slice` **之前**做一次 O(n) 线性预扫：统计 `[`/`{` 的嵌套层数（-字符串内不计），超过如 64 层直接返回与现状相同的"无法读取 YAML"错误。这不改变任何合法订阅的语义（mihomo 配置嵌套通常 <10 层），把恶意输入的成本从小时级压到毫秒级。
