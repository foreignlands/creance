f019-backlog — R4：F-019 佐证工具。单进程对 unix socket 发起 N 条非阻塞挂起连接
（EINPROGRESS），把 listen backlog（macOS std 默认 128）填满并溢出，使后续
connect() 得到 ECONNREFUSED——用于演示 retire_stale_record/close_gates 的
"unreachable ⇒ 删 record" 判定可被瞬时 backlog 压力触发。用法：
rustc -O filler.rs -o filler && ./filler <socket-path> [N]
