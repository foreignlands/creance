# STATE — 2026-11-20T07:30:00Z（R10 收敛轮第二试 · 终稿）

## 判定

**有新洞，建议继续循环**（修复 052-054 后再做收敛试）。R10 本为纯回归收敛轮，
night-11 四面中三面确认修复有效，但回归实测反出三个新洞（054 为 S2 端态的供给
fail-open，端态定标 S4 同 F-031）。

## 已覆盖（night-11 四面回归结论）

- **F-048 面 ✅ 修复确认**：r10-regression H1 21/21——包装形状过、翻转/夹带/裸
  数组/缺字段/非对象/null/空数组/大小写/超长全拒；api() 401/404 传播含状态码、
  非 JSON 拒、>1MiB take 截断拒（fail-closed）、299 宽容/199 拒（边界如实）。
  r9-regression h1.1/h1.2 按翻转语义读 = 修复成立（真实形状 Ok、裸数组 Err）。
- **F-049 面 ✗ 修复不完整 → F-052**：探针分支与 setup 写戳 fatal 两 claim 落地
  （探针矩阵 7/7：缺失+Running→Escaped、目录/chmod000/非UTF-8→Escaped、
  空文件→Escaped、缺失+无实例→NotEnforced）；**但 up 侧 stamp 读失败仍是
  `if let Ok` 跳过**（main.rs:666）——commit message/STATE 声称的第三 claim
  （"stamp 读失败=up 拒绝"）不在代码。实机：删 stamp → up rc=0；无实例时
  limactl start 自动从 template:default 创建**未供给原版 VM** 并启动成功。
- **F-050 面 ✅ 修复确认**：两处 store load Err → fatal（e2e：corrupt sources.json
  → gate-open rc=1 "代理配置不可读…请恢复私有配置备份"）；load Err 恒定串四形态
  （corrupt/>32MiB/version≠1/auth≠48）**无路径无 serde 细节**=无信息泄露；
  serve 侧敏感路径（select_and_apply/start_managed/applied）全部传播 Err
  fail-closed，仅 status_json/nodes_json `unwrap_or_default()` 显示降级（方向安全）。
- **F-051 面 ✓ 部分**：重建路径实机走通（setup×3 rc=0、戳在 create 成功后重写、
  guest-profile.json 跨重建保持同 username/token=同身份 by design、workspace 不动）；
  **但 setup 对运行中实例静默 `limactl delete -f` 直接摧毁**（lima 2.3.0 -f 可删
  running，rc=0 无确认无 "run creance stop" 提示——该 guard 分支实际不可达，S5
  观察记于 054 未验证想法）；**且发现 F-053：lima create 小写化实例名** →
  instance_running 名字恒等断裂，探针守卫失明（见下）。另：供给实机测试反出
  **F-054 供给 fail-open**（详见 findings）。

## 新发现（本轮 3 个，全部有实机/探针双证据）

- **F-052 S4**：up 侧 stamp 读失败跳过（claimed-but-not-shipped）；洗绿+原版 VM 启动。
- **F-053 S4**：lima create 小写化 vs creance 保留大小写 → `instance_running` 恒
  false → F-049 探针守卫与 gate-record 探针在 setup 产物上永不触发（实机：Running
  VM+删 stamp → escape-test 报 contained）；case-sensitive 卷上 F-051 重建检测必 miss。
- **F-054 S4**：首启供给截断 fail-open——无 --max-time 的 nodejs curl 挂死被杀，
  拓扑锁定+sudo 剥离整段未执行（实机 VM 交付 OUTPUT ACCEPT+免密 sudo+ipv6 开），
  up rc=0；[[ bashism（dash）恒 x64 退化次生。

## 下一步（按序 3 条）

1. **night-12 修复三连**：052（main.rs:666 改 match 拒绝+拒绝文案 E2E）、
   053（vmname 小写化单一事实源+instance_running 大小写不敏感兜底）、
   054（供给次序翻转：contract 段前置；curl --max-time；供给尾自检 iptables
   断言；[[ 改 POSIX）。修完复跑 r10-regression + 本 STATE 的实机矩阵。
2. R11 收敛第三试：四修复面 + 052-054 修复面纯回归；无新洞即写
   "审查收敛，建议停止循环"。
3. 停止后：0.6（Go 授权集 11 项+config 指纹三维 / multi-env——用户节奏）；
   剩余风险清单见下。

## 关键记忆（≤10 条，非显然事实）

1. `limactl start <不存在名>` 在 lima 2.3.0 **自动从 template:default 创建**
   （大写名保留）；`limactl create` 则**小写化**名字——lima 自身不一致。
2. macOS accept() 的 socket 继承 listener 的 O_NONBLOCK：假核心探针必须
   `set_nonblocking(false)`，否则 write_all ~8KB 处静默截断（r9 探针隐性竞态根源）。
3. api() 响应读 `take(1<<20)`：>1MiB body 被截断 → JSON 残缺 → Err（fail-closed
   已实测）；状态门 `(200..300)`：299 过、199 拒。
4. `creance_proxy::load` 四种 Err 全是恒定串，不含路径/serde 细节——e2e 泄露面干净。
5. 供给期 guest 无 tunnel：nodejs.org/claude.ai/apt 的可达性完全依赖宿主网络当季
   状态；apt 实测 20s 失败、nodejs curl 实测挂死 >8min 被击杀。
6. dash 对 `[[` 报 "[[: not found" 但最小复现**不** abort（赋值上下文）；供给脚本
   实机截断点是 curl 挂死本身，非 [[ 语法错。
7. `lima delete -f` 在 lima 2.3.0 可删运行中实例（setup-on-running 实测摧毁成功）。
8. escape-test 的 rc 必须直接捕获——管道（`| tail`）吃掉退出码（本轮两次踩坑，
   OPERATOR-PROMPT 铁律 4 的活例）。
9. guest-profile.json（host 侧）跨 VM 重建保持同 username/session_token——身份是
   profile 作用域非磁盘作用域；rotate_token 才是撤销手段。
10. 首启 provision 的 journal 关键字：`provision.system/00000000`；供给日志在
    journald（cloud-init 行内 trace），`/var/log/lima-provision-*.log` 不存在。

## 会话统计

- R10：3 findings（052/053/054），0 commit（仓库只读），1 新工具
  （harness/tools/r10-regression，32/32 探针 PASS）
- 累计 54 findings；51 已修复闭环，3 待修复（night-12）
- 基线：`sh scripts/ci.sh` 真实 RC=0（c76b2a3 / v0.5.5，14 套件全绿）
- 实机矩阵：setup×3 重建 / up 原版 VM / escape-test×3 / gate-open corrupt /
  delete -f / 手工供给重跑，全部临时 profile，已清理（/tmp 无残留、无 VM 残留、
  无孤儿 daemon/tunnel 进程）
