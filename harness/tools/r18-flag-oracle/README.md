# r18-flag-oracle

F-068 复现：真实 `guest_script()` 的 fs-flag-readable 段 + 真实 `environment_dir()` 路径推导，
在宿主上直接执行（guest 视角 = 宿主全盘可见，最大逃逸态），三场景：无旗标 / ESCAPE-BRIEF 指示位置 / 代码检查位置。
`cargo run`，RC=0 表示观测与 F-068 预测一致。
