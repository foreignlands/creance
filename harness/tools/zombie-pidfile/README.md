zombie-pidfile — R4：验证"未被 wait() 的 ssh 僵尸被 pidfile::alive 判活"（F-027 候选）。
独立 rustc 二进制，逐字复制 crates/creance-vm/src/pidfile.rs 的 process_start_token /
signal_alive / entry_alive 逻辑（无法从仓库外链接 workspace crate）。生产代码对 ssh
子进程无任何 wait（grep 验证，仅测试有），gate 守护是长活进程——ssh 秒退即成僵尸。
运行：sh run.sh
