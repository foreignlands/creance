//! 插件命令面：`plugin-list`（打印注册表）/ `plugin-call`（经 gate
//! 通道执行一次白名单调用=微型 gate-open）。

use super::*;

pub(crate) fn cmd_plugin_list(profile: String) -> i32 {
    let path = creance_vm::paths::join(&profile, "plugins.json");
    match std::fs::read_to_string(&path) {
        Ok(text) => {
            println!("{text}");
            0
        }
        Err(e) => fail(format!("无插件注册表 {path}：{e}")),
    }
}

pub(crate) fn cmd_plugin_call(profile: String, name: String, args: Vec<String>) -> i32 {
    let _ = profile; // 插件按全局 gate 记录定位
    let instance_dir = gate_instance_dir();
    let client = match creance_gate::gate::GateClient::open(&instance_dir) {
        Ok(c) => c,
        Err(e) => return fail(format!("gate 未运行：{e}")),
    };
    match client.plugin_call(&name, &args) {
        Ok(v) => {
            if let Some(s) = v.get("stdout").and_then(|x| x.as_str()) {
                print!("{s}");
            }
            if let Some(s) = v.get("stderr").and_then(|x| x.as_str()) {
                if !s.is_empty() {
                    eprint!("{s}");
                }
            }
            v.get("exit").and_then(|x| x.as_i64()).unwrap_or(1) as i32
        }
        Err(e) => fail(format!("插件调用被拒：{e}")),
    }
}
