use super::*;
use std::path::Path;

/// 指纹一键重置：轮换 guest 身份指纹（hostname/username/session_token，
/// 重建实例随之换 machine-id）。设计约束：必须先 `creance stop`——运行中
/// 的实例不能被 setup 的 rebuild 路径删除。客机配置文件不可读时拒绝盲删
/// （F-022 纪律：不可读的身份不重置）。
pub(crate) fn cmd_identity_reset(memory: u32, cpus: u32) -> i32 {
    let profile = profile();
    let instance = instance();
    if creance_vm::vm::instance_running(&profile, &instance) {
        return fail(format!(
            "实例 {instance} 仍在运行，先 `creance stop` 再重置指纹"
        ));
    }
    if let Err(e) = require_grant(&profile, "identity-reset") {
        return fail(e);
    }
    let guest_path = creance_vm::paths::join(&profile, creance_vm::guestprofile::FILENAME);
    if Path::new(&guest_path).exists() {
        if creance_vm::guestprofile::Profile::load_or_create(&profile).is_err() {
            return fail("客机配置不可读，拒绝重置身份；请修复权限或手动轮换".to_owned());
        }
        if let Err(e) = std::fs::remove_file(&guest_path) {
            return fail(format!("客机配置删除失败（{e}），重置中止"));
        }
    }
    cmd_setup(memory, cpus)
}

pub(crate) fn bundle_password() -> Result<String, String> {
    match std::env::var("CREANCE_BUNDLE_PASSWORD") {
        Ok(p) if !p.is_empty() => Ok(p),
        _ => Err("主密码从环境变量 CREANCE_BUNDLE_PASSWORD 读取（未设置或为空）".to_owned()),
    }
}

pub(crate) fn cmd_bundle_export(file: &str) -> i32 {
    let password = match bundle_password() {
        Ok(p) => p,
        Err(e) => return fail(e),
    };
    match creance_vm::bundle::export(&profile(), &password) {
        Ok(bytes) => match std::fs::write(file, &bytes) {
            Ok(()) => {
                println!("bundle 已导出（{} 字节，双层密封）→ {file}", bytes.len());
                0
            }
            Err(e) => fail(format!("写入 {file} 失败：{e}")),
        },
        Err(e) => fail(e),
    }
}

pub(crate) fn cmd_bundle_import(file: &str) -> i32 {
    let password = match bundle_password() {
        Ok(p) => p,
        Err(e) => return fail(e),
    };
    let bytes = match std::fs::read(file) {
        Ok(b) => b,
        Err(e) => return fail(format!("读取 {file} 失败：{e}")),
    };
    match creance_vm::bundle::import(&profile(), &password, &bytes) {
        Ok(n) => {
            println!("bundle 已解封落地（{n} 个身份文件）；`creance setup` 重建环境即可用");
            0
        }
        Err(e) => fail(e),
    }
}

/// Persona name discipline: a name is a directory under `bundles/` — only
/// [A-Za-z0-9_-] survives; anything else refuses before any path is built.
pub(crate) fn persona_dir(profile: &str, name: &str) -> Result<String, String> {
    if name.is_empty()
        || name.len() > 64
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return Err(format!("persona 名 {name:?} 非法（仅允许字母数字_-）"));
    }
    Ok(creance_vm::paths::join(
        &creance_vm::paths::join(profile, "bundles"),
        name,
    ))
}

pub(crate) fn cmd_persona_save(name: &str) -> i32 {
    let profile = profile();
    let dir = match persona_dir(&profile, name) {
        Ok(d) => d,
        Err(e) => return fail(e),
    };
    if let Err(e) = require_grant(&profile, &format!("persona-use-{name}")) {
        return fail(e);
    }
    if let Err(e) = std::fs::create_dir_all(&dir) {
        return fail(format!("persona 目录创建失败：{e}"));
    }
    let mut saved = 0usize;
    for f in creance_vm::bundle::FILES {
        let src = creance_vm::paths::join(&profile, f);
        if Path::new(&src).exists() {
            let dst = creance_vm::paths::join(&dir, f);
            if let Err(e) = std::fs::copy(&src, &dst) {
                return fail(format!("保存 {f} 失败：{e}"));
            }
            saved += 1;
        }
    }
    if saved == 0 {
        return fail("没有身份文件可快照".to_owned());
    }
    println!("persona {name} 已保存（{saved} 个文件）");
    0
}

pub(crate) fn cmd_persona_use(name: &str) -> i32 {
    let profile = profile();
    let instance = instance();
    if creance_vm::vm::instance_running(&profile, &instance) {
        return fail(format!(
            "实例 {instance} 仍在运行，先 `creance stop` 再切换 persona"
        ));
    }
    let dir = match persona_dir(&profile, name) {
        Ok(d) => d,
        Err(e) => return fail(e),
    };
    if !Path::new(&dir).is_dir() {
        return fail(format!(
            "persona {name} 不存在（`creance persona-list` 查看）"
        ));
    }
    // 原子语义：先验全部源文件可读可写回，再动手——中途失败不留下半换
    // 状态。身份文件逐一覆盖写回（目标已存在是常态，bundle 导入才是
    // 拒绝覆盖的场景）。
    let mut staged = Vec::new();
    for f in creance_vm::bundle::FILES {
        let src = creance_vm::paths::join(&dir, f);
        match std::fs::read(&src) {
            Ok(bytes) => staged.push((f.to_string(), bytes)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return fail(format!("persona {name} 的 {f} 不可读（{e}），切换中止")),
        }
    }
    if staged.is_empty() {
        return fail(format!("persona {name} 是空的，拒绝切换"));
    }
    for (f, bytes) in &staged {
        let dst = creance_vm::paths::join(&profile, f);
        if let Err(e) = creance_vm::write_private_atomic(&dst, bytes) {
            return fail(format!("换回 {f} 失败：{e}"));
        }
    }
    // 持久 device_id 物理隔离：身份文件换回后必须重建 VM 磁盘，否则
    // guest 内的 hostname/username/machine-id 仍是上一个 persona 的。
    println!("persona 已切换到 {name}，重建实例……");
    cmd_setup(8, 4)
}

/// 整机迁移导出：persona 文件 + bundles/ 快照树全量进迁移包（与
/// Bundle 容器一体：argon2id→XChaCha20-Poly1305 双层密封）。
pub(crate) fn cmd_migrate_export(file: &str) -> i32 {
    let password = match bundle_password() {
        Ok(p) => p,
        Err(e) => return fail(e),
    };
    match creance_vm::bundle::export_with(&profile(), &password, true) {
        Ok(bytes) => match std::fs::write(file, &bytes) {
            Ok(()) => {
                println!(
                    "迁移包已导出（{} 字节，含 persona 快照树）→ {file}",
                    bytes.len()
                );
                0
            }
            Err(e) => fail(format!("写入 {file} 失败：{e}")),
        },
        Err(e) => fail(e),
    }
}

pub(crate) fn cmd_approve(action: &str) -> i32 {
    let cfg = match config::load(&config::config_path()) {
        Ok(c) => c,
        Err(e) => return fail(e),
    };
    match creance::approve::request_approval(&profile(), &cfg, action) {
        Ok(()) => {
            println!("已批准：{action}（10 分钟内对该操作免复批）");
            0
        }
        Err(e) => fail(e),
    }
}

/// 配置了审批通道时要求持有效批条；未配置即放行（通道是加固项）。
pub(crate) fn require_grant(profile: &str, action: &str) -> Result<(), String> {
    let cfg = config::load(&config::config_path())?;
    if creance::approve::has_grant(profile, &cfg, action) {
        return Ok(());
    }
    Err(format!(
        "{action} 需手机批准：先 `creance approve {action}` 并在手机上回执"
    ))
}

pub(crate) fn cmd_persona_list() -> i32 {
    let dir = creance_vm::paths::join(&profile(), "bundles");
    let Ok(rd) = std::fs::read_dir(&dir) else {
        println!("（无已保存 persona）");
        return 0;
    };
    let mut names: Vec<String> = rd
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_dir())
        .filter_map(|e| e.file_name().to_str().map(|s| s.to_owned()))
        .collect();
    names.sort();
    for n in &names {
        println!("{n}");
    }
    if names.is_empty() {
        println!("（无已保存 persona）");
    }
    0
}

/// keychain set：秘密从 stdin 读一行——argv 是 ps 可见的，永不走命令行。
pub(crate) fn cmd_keychain_set(entry: &str) -> i32 {
    let mut buf = String::new();
    if std::io::stdin().read_line(&mut buf).is_err() {
        return fail("stdin 读取失败".to_owned());
    }
    let secret = buf.trim_end_matches(['\n', '\r']);
    if secret.is_empty() {
        return fail("秘密为空——从 stdin 传入一行".to_owned());
    }
    match creance_vm::secret::store(entry, secret) {
        Ok(()) => {
            println!("已写入钥匙串：keychain:{entry}");
            0
        }
        Err(e) => fail(e),
    }
}

pub(crate) fn cmd_keychain_delete(entry: &str) -> i32 {
    match creance_vm::secret::delete(entry) {
        Ok(()) => {
            println!("已删除：keychain:{entry}");
            0
        }
        Err(e) => fail(e),
    }
}

/// 把 config.json 里的明文秘密搬进钥匙串：proxy_url 带密码的 userinfo、
/// approval_bot_token。先写备份再改写——迁移失败时原文件可手工恢复。
pub(crate) fn cmd_keychain_migrate() -> i32 {
    let path = config::config_path();
    let mut cfg = match config::load(&path) {
        Ok(c) => c,
        Err(e) => return fail(e),
    };
    let mut moved: Vec<String> = Vec::new();
    // proxy_url：只有带密码 userinfo（scheme://user:pass@host）才值得挪——
    // 本机回环端点（socks5://127.0.0.1:…）不是秘密。
    if !creance_vm::secret::is_reference(&cfg.proxy_url) && proxy_url_has_password(&cfg.proxy_url) {
        if let Err(e) = creance_vm::secret::store("proxy_url", &cfg.proxy_url) {
            return fail(e);
        }
        cfg.proxy_url = "keychain:proxy_url".to_owned();
        moved.push("proxy_url".to_owned());
    }
    if !cfg.approval_bot_token.is_empty()
        && !creance_vm::secret::is_reference(&cfg.approval_bot_token)
    {
        if let Err(e) = creance_vm::secret::store("approval_bot_token", &cfg.approval_bot_token) {
            return fail(e);
        }
        cfg.approval_bot_token = "keychain:approval_bot_token".to_owned();
        moved.push("approval_bot_token".to_owned());
    }
    if moved.is_empty() {
        println!("无需迁移：未发现明文秘密（或已是 keychain 引用）");
        return 0;
    }
    let backup = format!("{path}.pre-keychain-bak");
    if let Ok(bytes) = std::fs::read(&path)
        && let Err(e) = creance_vm::write_private_atomic(&backup, &bytes)
    {
        return fail(format!("备份写入失败，未迁移：{e}"));
    }
    match config::write_private_config(&path, &cfg) {
        Ok(()) => {
            println!("已迁移：{}（备份 {}）", moved.join(", "), backup);
            0
        }
        Err(e) => fail(format!("配置改写失败：{e}")),
    }
}

/// scheme://user:pass@host 且 pass 非空。
fn proxy_url_has_password(url: &str) -> bool {
    let Some(rest) = url.split("://").nth(1) else {
        return false;
    };
    let Some(authority) = rest.split('/').next() else {
        return false;
    };
    let Some(userinfo) = authority
        .split('@')
        .next()
        .filter(|_| authority.contains('@'))
    else {
        return false;
    };
    userinfo
        .split_once(':')
        .is_some_and(|(_, pass)| !pass.is_empty())
}

/// apply：声明式重建。运行中的实例拒绝——重建覆写身份，运行中覆写
/// 会让 guest 与宿主记录错位（与 identity-reset 同一纪律）。
pub(crate) fn cmd_apply(file: &str) -> i32 {
    let decl = match creance::apply::load_declaration(file) {
        Ok(d) => d,
        Err(e) => return fail(e),
    };
    let prof = profile();
    let inst = instance();
    if creance_vm::vm::instance_running(&prof, &inst) {
        return fail(format!("实例 {inst} 仍在运行，先 `creance stop` 再 apply"));
    }
    match creance::apply::apply(&prof, &decl) {
        Ok(notes) => {
            for n in &notes {
                println!("{n}");
            }
            println!("重建就绪：creance setup && creance up");
            0
        }
        Err(e) => fail(e),
    }
}
