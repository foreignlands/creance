//! 终端通道（0.8.5 下半期）：浏览器 xterm.js ↔ WebSocket ↔ ssh -tt ↔
//! guest shell/agent。设计决议见 docs/PRODUCT-DEEP-0.8。
//!
//! 安全纪律：
//! - 命令模板来自编译期注册表常量，用户输入只有 agent id 与尺寸；
//! - ssh 走 apply_ssh_options 全部纪律（pinned host key/batch/strip env）；
//! - WS 关闭=ssh 子进程必被杀（kill 在 scope end，恐慌路径也覆盖）；
//! - 实例未运行=升级前就拒绝，不开半通道。

use crate::ws::{self, Frame};
use std::io::{Read, Write};
use std::process::{Child, Command, Stdio};

pub struct TermParams {
    pub launch: String,
    pub cols: u16,
    pub rows: u16,
}

/// 校验+提取 ws 握手参数；key 缺失或非 base64-ish 即拒绝。
pub fn handshake_key(fields: &[(String, String)]) -> Option<String> {
    let mut upgrade = false;
    let mut key = None;
    for (k, v) in fields {
        if k.eq_ignore_ascii_case("upgrade") && v.eq_ignore_ascii_case("websocket") {
            upgrade = true;
        }
        if k.eq_ignore_ascii_case("sec-websocket-key") {
            key = Some(v.trim().to_owned());
        }
    }
    if !upgrade {
        return None;
    }
    let k = key?;
    if k.len() < 8
        || k.len() > 64
        || !k
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "+/=".contains(c))
    {
        return None;
    }
    Some(k)
}

/// 在已升级的连接上跑终端会话。阻塞至任一侧关闭。
pub fn run(
    mut stream: std::net::TcpStream,
    key: &str,
    profile: &str,
    params: TermParams,
) -> Result<(), String> {
    // WS 会话是长连接——handle() 的 10s 超时对终端是错的
    let _ = stream.set_read_timeout(None);
    let accept = ws::accept_key(key);
    let resp = format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
    );
    stream
        .write_all(resp.as_bytes())
        .map_err(|e| e.to_string())?;

    let instance = crate::serve::running_instance(profile)?;
    let target = creance_vm::vm::ssh_target(profile, &instance)?;
    let mut cmd = Command::new("ssh");
    creance_vm::vm::apply_ssh_options(&mut cmd, &target);
    cmd.arg("-o")
        .arg("StrictHostKeyChecking=yes")
        // -tt 强制 guest 侧 pty——TUI agent 的硬需求；host 侧无需 tty
        .arg("-tt")
        .arg("127.0.0.1")
        .arg(format!(
            "stty rows {} cols {} 2>/dev/null; exec {}",
            params.rows, params.cols, params.launch
        ));
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut child: Child = cmd.spawn().map_err(|e| format!("ssh 通道失败：{e}"))?;
    let mut child_stdout = child.stdout.take().expect("piped");
    let mut child_stdin = child.stdin.take().expect("piped");

    // ssh→browser 泵线程
    let mut up = stream.try_clone().map_err(|e| e.to_string())?;
    let pump = std::thread::spawn(move || {
        let mut buf = [0u8; 8192];
        loop {
            match child_stdout.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if ws::write_frame(&mut up, 0x2, &buf[..n]).is_err() {
                        break;
                    }
                }
            }
        }
    });

    // browser→ssh 主循环（ping 回 pong，close/错误即终）
    let mut stdin_open = true;
    while let Some(frame) = ws::read_frame(&mut stream) {
        match frame {
            Frame::Binary(data) | Frame::Text(data) => {
                if stdin_open && child_stdin.write_all(&data).is_err() {
                    stdin_open = false;
                }
            }
            Frame::Ping(p) => {
                let _ = ws::write_frame(&mut stream, 0xA, &p);
            }
            Frame::Close => break,
            Frame::Pong(_) => {}
        }
    }
    // 终了纪律：browser 侧断开=ssh 必死，不留孤儿会话占 guest
    let _ = child.kill();
    let _ = child.wait();
    let _ = pump.join();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handshake_requires_upgrade_and_sane_key() {
        assert!(
            handshake_key(&[(
                "sec-websocket-key".into(),
                "dGhlIHNhbXBsZSBub25jZQ==".into()
            )])
            .is_none()
        );
        assert!(
            handshake_key(&[
                ("upgrade".into(), "websocket".into()),
                (
                    "sec-websocket-key".into(),
                    "dGhlIHNhbXBsZSBub25jZQ==".into()
                ),
            ])
            .is_some()
        );
        assert!(
            handshake_key(&[
                ("upgrade".into(), "websocket".into()),
                ("sec-websocket-key".into(), "ab".into()),
            ])
            .is_none()
        );
    }
}
