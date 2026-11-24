//! creance desktop shell — a thin Tauri window over `creance::serve`.
//!
//! 壳不重新发明 UI：进程内起 workbench 的 127.0.0.1 服务，窗口指过去；
//! 托盘轮询 /api/status 呈现存活态；IPC 命令直调 creance-vm 的 `i32`
//! 面（与 CLI 同一条代码路径，不做第二条逻辑线）。

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::time::Duration;

use tauri::tray::TrayIconBuilder;
use tauri::{WebviewUrl, WebviewWindowBuilder};

fn profile() -> String {
    let path = creance_vm::config::config_path();
    Path::new(&path)
        .parent()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|| ".".to_owned())
}

fn status_get(port: u16) -> Option<serde_json::Value> {
    let mut s = TcpStream::connect(("127.0.0.1", port)).ok()?;
    s.set_read_timeout(Some(Duration::from_secs(2))).ok()?;
    s.write_all(b"GET /api/status HTTP/1.0\r\n\r\n").ok()?;
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).ok()?;
    let text = String::from_utf8_lossy(&buf);
    let body = text.split("\r\n\r\n").nth(1)?;
    serde_json::from_str(body).ok()
}

#[tauri::command]
fn creance_up() -> i32 {
    let profile = profile();
    let instance =
        creance_vm::vm::instance_name(&profile, &creance_vm::vm::environment_dir(&profile));
    creance_vm::vm::up(&profile, &instance)
}

#[tauri::command]
fn creance_stop() -> i32 {
    let profile = profile();
    let instance =
        creance_vm::vm::instance_name(&profile, &creance_vm::vm::environment_dir(&profile));
    creance_vm::vm::stop_vm(&profile, &instance)
}

#[tauri::command]
fn proxy_start() -> i32 {
    let profile = profile();
    match creance_proxy::start_managed(&profile, &creance_vm::config::config_path()) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("creance: {e}");
            1
        }
    }
}

fn main() {
    let profile = profile();
    let config_path = creance_vm::config::config_path();

    // 进程内起 workbench（端口=系统分配的空闲口），窗口再指过去。
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind loopback");
    let port = listener.local_addr().unwrap().port();
    drop(listener); // serve 重新绑定同一端口
    {
        let (profile, config_path) = (profile.clone(), config_path.clone());
        std::thread::spawn(move || {
            if let Err(e) = creance::serve::serve(&profile, &config_path, port) {
                eprintln!("creance serve stopped: {e}");
            }
        });
    }

    tauri::Builder::default()
        .setup(move |app| {
            let url: tauri::Url = format!("http://127.0.0.1:{port}").parse().unwrap();
            WebviewWindowBuilder::new(app, "main", WebviewUrl::External(url))
                .title("creance")
                .inner_size(1024.0, 720.0)
                .build()?;

            let tray = TrayIconBuilder::new()
                .icon(app.default_window_icon().unwrap().clone())
                .tooltip("creance — 巡检中")
                .build(app)?;
            // 托盘巡检：每 5s 采一次 /api/status。
            std::thread::spawn(move || loop {
                let tip = match status_get(port) {
                    Some(v) => {
                        let core = v["core_running"].as_bool().unwrap_or(false);
                        let nodes = v["nodes"].as_u64().unwrap_or(0);
                        format!(
                            "creance — 核心{} · 节点 {} · {}",
                            if core { "运行" } else { "停止" },
                            nodes,
                            v["instance"].as_str().unwrap_or("?")
                        )
                    }
                    None => "creance — serve 不可达".to_owned(),
                };
                let _ = tray.set_tooltip(Some(&tip));
                std::thread::sleep(Duration::from_secs(5));
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![creance_up, creance_stop, proxy_start])
        .run(tauri::generate_context!())
        .expect("error while running creance desktop");
}
