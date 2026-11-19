c3-gate-hammer — R4：gate 状态机并发黑盒（C3）。
对运行中的 profile 反复并发 gate-open/gate-close/状态采样，检查不变量：
closed ⇒ 隧道进程与 pid 文件消失；open ⇒ 恰一条 ssh -R 隧道活着；
record 与 gate.pid 一致；无常驻双守护。
用法：sh hammer.sh <profile-abs-path> <rounds>
依赖：target/release/creance、jq、curl（unix socket）。
