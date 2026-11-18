//! The proxy core's lifecycle: bundled mihomo, launchd-managed on macOS,
//! health-checked through its private control socket.
//!
//! The core is never searched for on PATH — only the application bundle
//! carries it. Readiness is judged by the control socket, not by process
//! existence.

#![allow(unsafe_code)] // FFI to libc: statfs/sysctl/signal — audited, no unchecked input
use crate::runtime::{bind_interface, bound_interface};
use crate::{dir, socket, write_private, Store, GROUP};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpListener};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::atomic::{AtomicI32, Ordering};
use std::time::{Duration, Instant};

/// The start-readiness poll cadence and budget.
const START_POLL: Duration = Duration::from_millis(100);
const START_BUDGET: Duration = Duration::from_secs(10);

/// The bundled core binary. Never searches PATH or another app's bundle.
pub fn core_path() -> Result<String, String> {
    let exe = std::env::current_exe()
        .map_err(|e| e.to_string())?
        .to_string_lossy()
        .into_owned();
    let exe_dir = Path::new(&exe)
        .parent()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default();
    let name = if cfg!(windows) {
        "mihomo.exe"
    } else {
        "mihomo"
    };
    for candidate in [
        format!("{exe_dir}/{name}"),
        format!("{exe_dir}/../proxy-core/{name}"),
    ] {
        if let Ok(info) = std::fs::metadata(&candidate) {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if info.is_file() && info.permissions().mode() & 0o111 != 0 {
                    return Ok(candidate);
                }
            }
            #[cfg(not(unix))]
            {
                if info.is_file() {
                    return Ok(candidate);
                }
            }
        }
    }
    Err(
        "Cage 随附代理核心缺失，请重新安装完整应用；开发构建请运行 scripts/fetch-proxy-core.sh"
            .to_owned(),
    )
}

/// `mihomo -t` against the generated config. Original store files are never
/// touched; the check runs on a private temporary copy.
pub fn validate(profile: &str, store: &Store) -> Result<(), String> {
    let core = core_path()?;
    let bytes = store.runtime_yaml(profile)?;
    let proxy_dir = dir(profile);
    creance_vm::private::ensure_private_dir(&proxy_dir).map_err(|e| e.to_string())?;
    let (mut file, tmp) = creance_vm::private::create_private_temp(&proxy_dir, "validate")
        .map_err(|e| e.to_string())?;
    if file.write_all(&bytes).is_err() {
        let _ = std::fs::remove_file(&tmp);
        return Err("无法写入校验配置".to_owned());
    }
    drop(file);
    let result = run_command(&core, &["-t", "-d", &proxy_dir, "-f", &tmp]);
    let _ = std::fs::remove_file(&tmp);
    if result.is_err() {
        return Err("随附的 Mihomo 核心未通过配置校验，请核对节点协议和参数；可在设置的“日志与诊断”中导出诊断包查看校验记录；原配置已保留".to_owned());
    }
    Ok(())
}

/// One HTTP request over the core's private control socket.
fn api(profile: &str, method: &str, path: &str) -> Result<serde_json::Value, String> {
    use std::os::unix::net::UnixStream;
    let mut stream =
        UnixStream::connect(socket(profile)).map_err(|_| "代理控制通道不可达".to_owned())?;
    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));
    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: cage-proxy\r\nConnection: close\r\nContent-Type: application/json\r\n\r\n"
    );
    stream
        .write_all(req.as_bytes())
        .map_err(|e| e.to_string())?;
    let mut raw = Vec::new();
    stream
        .take(1 << 20)
        .read_to_end(&mut raw)
        .map_err(|e| e.to_string())?;
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or("代理控制通道响应无效")?;
    let head = String::from_utf8_lossy(&raw[..split]).into_owned();
    let status: u16 = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .ok_or("代理控制通道响应无效")?;
    if !(200..300).contains(&status) {
        return Err(format!("代理控制通道返回 HTTP {status}"));
    }
    serde_json::from_slice(&raw[split + 4..]).map_err(|e| e.to_string())
}

/// Whether the running core is the one this store describes: same port, same
/// binding, same selection. Anything else counts as not running.
pub fn check_running(profile: &str, store: &Store) -> Result<(), String> {
    let bound = bound_interface(
        &Path::new(&dir(profile))
            .join("config.yaml")
            .to_string_lossy(),
    )?;
    if bound.is_empty() {
        return Err("readiness: no bound interface".to_owned());
    }
    let configs = api(profile, "GET", "/configs")?;
    let port_matches = configs
        .get("mixed-port")
        .and_then(serde_json::Value::as_u64)
        == Some(store.port as u64);
    if !port_matches {
        return Err("readiness: port".to_owned());
    }
    if configs.get("interface-name").and_then(|v| v.as_str()) != Some(bound.as_str()) {
        return Err("readiness: interface".to_owned());
    }
    if configs.get("unified-delay") != Some(&serde_json::Value::Bool(true)) {
        return Err("readiness: unified-delay".to_owned());
    }
    let group = api(profile, "GET", &format!("/proxies/{GROUP}"))?;
    if group.get("now").and_then(|v| v.as_str()) != Some(store.selected.as_str()) {
        return Err("readiness: selection".to_owned());
    }
    Ok(())
}

/// Whether the running core matches this store.
pub fn running(profile: &str, store: &Store) -> bool {
    check_running(profile, store).is_ok()
}

fn service_label(profile: &str) -> String {
    let h = Sha256::digest(profile.as_bytes());
    format!("local.claude-cage.managed-proxy.{}", hex::encode(&h[..4]))
}

fn service_path(profile: &str) -> String {
    Path::new(&dir(profile))
        .join("managed-service.plist")
        .to_string_lossy()
        .into_owned()
}

/// Stops the managed core. A missing service means nothing to stop.
pub fn stop(profile: &str) -> Result<(), String> {
    if cfg!(not(target_os = "macos")) {
        return Err("内置代理当前支持 macOS".to_owned());
    }
    if !Path::new(&service_path(profile)).exists() {
        return Ok(());
    }
    let domain = format!("gui/{}", uid());
    let label = format!("{domain}/{}", service_label(profile));
    if run_command("launchctl", &["print", &label]).is_err() {
        // Not loaded: a leftover plist from a failed bootstrap is residue.
        let _ = std::fs::remove_file(service_path(profile));
        return Ok(());
    }
    if run_command("launchctl", &["bootout", &domain, &service_path(profile)]).is_err() {
        return Err("未能停止 Cage 专属代理进程".to_owned());
    }
    Ok(())
}

/// Starts (or refreshes) the managed core for this profile's applied node.
pub fn start(profile: &str, store: &Store) -> Result<(), String> {
    if cfg!(not(target_os = "macos")) {
        return Err("内置代理当前支持 macOS".to_owned());
    }
    let name = physical_interface()?;
    let path = Path::new(&dir(profile))
        .join("config.yaml")
        .to_string_lossy()
        .into_owned();
    let bound = bound_interface(&path).unwrap_or_default();
    if bound == name && running(profile, store) {
        return Ok(());
    }
    validate(profile, store)?;
    stop(profile)?;
    // Never attach to or kill an unknown listener, even if it uses our port.
    if TcpListener::bind((Ipv4Addr::LOCALHOST, store.port)).is_err() {
        return Err("Cage 代理端口已被占用，请更换独立端口".to_owned());
    }
    core_path()?;
    let sock = socket(profile);
    let sock_dir = Path::new(&sock)
        .parent()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default();
    std::fs::create_dir_all(&sock_dir).map_err(|e| e.to_string())?;
    creance_vm::private::ensure_private_dir(&sock_dir).map_err(|e| e.to_string())?;
    let bytes = store.runtime_yaml(profile)?;
    let bytes = bind_interface(&bytes, &name)?;
    write_private(&path, &bytes)?;
    let _ = std::fs::remove_file(&sock);

    // The launchd job runs fully self-contained inside the proxy directory:
    // a copy of this binary as the relay, and the bundled core beside it.
    // Release bundles install both next to each other anyway, and a copy
    // keeps the job independent of a moving build directory.
    let exe = std::env::current_exe()
        .map_err(|e| e.to_string())?
        .to_string_lossy()
        .into_owned();
    let relay_bin = Path::new(&dir(profile)).join("cage-relay");
    copy_executable_if_changed(&exe, relay_bin.to_string_lossy().as_ref())?;
    let core = core_path()?;
    let core_copy = Path::new(&dir(profile)).join("mihomo");
    copy_executable_if_changed(&core, core_copy.to_string_lossy().as_ref())?;
    let config_path = match std::env::var(creance_vm::config::CONFIG_ENV) {
        Ok(p) if !p.is_empty() => p,
        _ => format!("{profile}/config.json"),
    };
    let plist = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\
<plist version=\"1.0\"><dict>\
<key>Label</key><string>{}</string>\
<key>ProgramArguments</key><array><string>{}</string><string>log-relay</string><string>proxy</string></array>\
<key>EnvironmentVariables</key><dict>\
<key>HOME</key><string>{}</string>\
<key>PATH</key><string>/usr/bin:/bin</string>\
<key>{}</key><string>{}</string>\
</dict>\
<key>StandardOutPath</key><string>{}</string>\
<key>StandardErrorPath</key><string>{}</string>\
<key>RunAtLoad</key><true/></dict></plist>",
        xml_escape(&service_label(profile)),
        xml_escape(&relay_bin.to_string_lossy()),
        xml_escape(&dir(profile)),
        creance_vm::config::CONFIG_ENV,
        xml_escape(&config_path),
        xml_escape(&Path::new(&dir(profile)).join("launchd-stdout.log").to_string_lossy()),
        xml_escape(&Path::new(&dir(profile)).join("launchd-stderr.log").to_string_lossy()),
    );
    write_private(&service_path(profile), plist.as_bytes())?;
    let domain = format!("gui/{}", uid());
    if run_command("launchctl", &["bootstrap", &domain, &service_path(profile)]).is_err() {
        // Roll the half-started state back off so a retry starts clean.
        let _ = run_command("launchctl", &["bootout", &domain, &service_path(profile)]);
        let _ = std::fs::remove_file(service_path(profile));
        return Err("无法启动 Cage 自带代理核心".to_owned());
    }
    let deadline = Instant::now() + START_BUDGET;
    while Instant::now() < deadline {
        if running(profile, store) {
            std::fs::set_permissions(&sock, std::fs::Permissions::from_mode(0o600))
                .map_err(|e| e.to_string())?;
            return Ok(());
        }
        std::thread::sleep(START_POLL);
    }
    let _ = stop(profile);
    Err("代理核心启动超时，请查看私有代理日志".to_owned())
}

/// The `cage log-relay proxy` entry: owns the core's stdout/stderr capture so
/// a crash is recorded, and forwards termination signals to the child so
/// launchd's bootout reaches mihomo. Every relay-side failure is logged too —
/// under launchd there is no stderr to look at.
pub fn log_relay_proxy(profile: &str) -> i32 {
    use std::io::Write as _;
    let proxy_dir = dir(profile);
    let log_path = Path::new(&proxy_dir).join("proxy.log");
    let mut log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path);
    let mut report = |message: &str| {
        let _ = log.as_mut().map(|f| {
            let _ = writeln!(f, "cage relay: {message}");
        });
    };
    let Ok(core) = core_path() else {
        report("bundled core missing");
        return 1;
    };
    let config = Path::new(&proxy_dir).join("config.yaml");
    // Signal disposition is installed BEFORE the child exists: a SIGTERM
    // arriving between spawn and handler setup would otherwise kill the
    // relay and orphan mihomo.
    unsafe {
        CHILD_PID.store(0, Ordering::Relaxed);
        libc::signal(
            libc::SIGTERM,
            forward_signal as extern "C" fn(libc::c_int) as libc::sighandler_t,
        );
        libc::signal(
            libc::SIGINT,
            forward_signal as extern "C" fn(libc::c_int) as libc::sighandler_t,
        );
    }
    let mut child = match std::process::Command::new(&core)
        .arg("-d")
        .arg(&proxy_dir)
        .arg("-f")
        .arg(&config)
        // The core inherits NOTHING from the user's shell: host proxies and
        // credentials (HTTP_PROXY, ANTHROPIC keys, ...) must not reach it.
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", &proxy_dir)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            report(&format!("spawn mihomo failed: {e}"));
            return 1;
        }
    };
    CHILD_PID.store(child.id() as i32, Ordering::Relaxed);
    // The log handle now moves into the writer thread; `report` above owns
    // it until the child is up, so the file is opened again for streaming.
    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(Path::new(&proxy_dir).join("proxy.log"));
    let mut sink: Box<dyn Write + Send> = match log {
        Ok(f) => Box::new(f),
        Err(_) => Box::new(std::io::sink()),
    };
    let (tx, rx) = std::sync::mpsc::channel::<Vec<u8>>();
    let writer = std::thread::spawn(move || {
        while let Ok(chunk) = rx.recv() {
            let _ = sink.write_all(&chunk);
        }
        let _ = sink.flush();
    });
    let mut pipes: Vec<Box<dyn Read + Send>> = Vec::new();
    if let Some(s) = child.stdout.take() {
        pipes.push(Box::new(s));
    }
    if let Some(s) = child.stderr.take() {
        pipes.push(Box::new(s));
    }
    for mut pipe in pipes {
        let tx = tx.clone();
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            while let Ok(n) = pipe.read(&mut buf) {
                if n == 0 {
                    break;
                }
                if tx.send(buf[..n].to_vec()).is_err() {
                    break;
                }
            }
        });
    }
    let status = child.wait();
    CHILD_PID.store(0, Ordering::Relaxed);
    drop(tx);
    let _ = writer.join();
    match &status {
        Ok(s) if s.success() => {}
        Ok(s) => report(&format!("mihomo terminated: {s}")),
        Err(e) => report(&format!("mihomo wait failed: {e}")),
    }
    match status {
        Ok(s) if s.success() => 0,
        _ => 1,
    }
}

static CHILD_PID: AtomicI32 = AtomicI32::new(0);

extern "C" fn forward_signal(sig: libc::c_int) {
    let pid = CHILD_PID.load(Ordering::Relaxed);
    if pid > 0 {
        unsafe { libc::kill(pid, sig) };
    }
}

fn run_command(program: &str, args: &[&str]) -> Result<(), String> {
    std::process::Command::new(program)
        .args(args)
        .output()
        .map(|_| ())
        .map_err(|e| e.to_string())
}

fn uid() -> u32 {
    unsafe { libc::getuid() }
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('\"', "&quot;")
}

/// Copies an executable into the proxy directory unless the destination
/// already has identical content (sha256; size is only a cheap pre-filter).
fn copy_executable_if_changed(src: &str, dst: &str) -> Result<(), String> {
    let src_bytes = std::fs::read(src).map_err(|e| e.to_string())?;
    if let Ok(dst_bytes) = std::fs::read(dst) {
        if dst_bytes.len() == src_bytes.len()
            && sha2::Sha256::digest(&dst_bytes) == sha2::Sha256::digest(&src_bytes)
        {
            return Ok(());
        }
    }
    std::fs::write(dst, &src_bytes).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dst, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// The system's preferred reachable IPv4 hardware port. A route through utun
/// is not a physical uplink, even when it is the default.
pub fn physical_interface() -> Result<String, String> {
    if !cfg!(target_os = "macos") {
        return Err("物理网卡识别当前支持 macOS".to_owned());
    }
    let hardware = std::process::Command::new("/usr/sbin/networksetup")
        .arg("-listallhardwareports")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .map_err(|_| "无法读取物理网卡，请检查主机网络后重试".to_owned())?;
    let route = std::process::Command::new("/sbin/route")
        .args(["-n", "get", "default"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default();
    let nwi = std::process::Command::new("/usr/sbin/scutil")
        .arg("--nwi")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default();
    let usable = usable_interfaces()?;
    select_physical_interface(&route, &hardware, &nwi, &usable)
}

/// Interfaces that are up, not loopback, and carry a global IPv4 address.
fn usable_interfaces() -> Result<std::collections::HashSet<String>, String> {
    unsafe { collect_interfaces() }.map_err(|e| format!("无法枚举网络接口：{e}"))
}

unsafe fn collect_interfaces() -> Result<std::collections::HashSet<String>, String> {
    use std::ffi::CStr;
    use std::net::Ipv4Addr;
    let mut out = std::collections::HashSet::new();
    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    if libc::getifaddrs(&mut head) != 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    let mut cursor = head;
    while !cursor.is_null() {
        let ifa = &*cursor;
        let flags = ifa.ifa_flags as u32;
        if flags & libc::IFF_UP as u32 != 0 && flags & libc::IFF_LOOPBACK as u32 == 0 {
            // macOS spells the address `ifa_addr`; Linux nests it in a union.
            #[cfg(target_os = "macos")]
            let addr_ptr = ifa.ifa_addr;
            #[cfg(all(unix, not(target_os = "macos")))]
            let addr_ptr = unsafe { ifa.ifa_ifu.ifu_addr };
            if !addr_ptr.is_null() && unsafe { (*addr_ptr).sa_family } == libc::AF_INET as u8 {
                let sin = addr_ptr as *const libc::sockaddr_in;
                let octets = unsafe { (*sin).sin_addr.s_addr.to_ne_bytes() };
                let ip = Ipv4Addr::from(octets);
                if !ip.is_loopback() && !ip.is_link_local() && !ip.is_unspecified() {
                    let name = CStr::from_ptr(ifa.ifa_name).to_string_lossy().into_owned();
                    out.insert(name);
                }
            }
        }
        cursor = ifa.ifa_next;
    }
    libc::freeifaddrs(head);
    Ok(out)
}

/// macOS also exposes packet tunnels, bridges, VM links, AWDL and other
/// service interfaces. They can carry an IPv4 address, but they are not a
/// physical uplink and must not become the proxy's binding.
fn is_virtual_mac_interface(name: &str) -> bool {
    const PREFIXES: &[&str] = &[
        "utun", "bridge", "vmen", "vmenet", "vmnet", "tap", "lima", "awdl", "llw", "p2p", "gif",
        "stf", "anpi", "ap",
    ];
    let lower = name.to_lowercase();
    let stem = lower.trim_end_matches(|c: char| c.is_ascii_digit());
    stem.len() < lower.len() && PREFIXES.contains(&stem)
}

/// Chooses the default route's interface among the reachable physical ones,
/// preferring scutil's network-priority order.
fn select_physical_interface(
    route: &str,
    hardware: &str,
    nwi: &str,
    usable: &std::collections::HashSet<String>,
) -> Result<String, String> {
    let mut physical = std::collections::HashSet::new();
    for line in hardware.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() == 2
            && fields[0] == "Device:"
            && usable.contains(fields[1])
            && !is_virtual_mac_interface(fields[1])
        {
            physical.insert(fields[1].to_owned());
        }
    }
    // scutil lists interfaces in network priority order. Only its reachable
    // IPv4 section is relevant to the proxy's IPv4 infrastructure transport.
    let (mut in_ipv4, mut candidate) = (false, String::new());
    let mut reachable = Vec::new();
    for line in nwi.lines() {
        let line = line.trim();
        if line.starts_with("IPv4 network interface information") {
            in_ipv4 = true;
        } else if line.starts_with("IPv6 network interface information") {
            break;
        }
        if !in_ipv4 {
            continue;
        }
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() >= 3 && fields[1] == ":" && fields[2] == "flags" {
            candidate = fields[0].to_owned();
        }
        if line.starts_with("reach")
            && line.contains("(Reachable)")
            && physical.contains(&candidate)
        {
            reachable.push(candidate.clone());
        }
    }
    for line in route.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() == 2 && fields[0] == "interface:" {
            for name in &reachable {
                if fields[1] == name {
                    return Ok(name.clone());
                }
            }
        }
    }
    reachable
        .first()
        .cloned()
        .ok_or_else(|| "未找到可用的物理 IPv4 网卡；Cage 外网保持关闭，请连接网络后重试".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn virtual_interface_detection() {
        for name in [
            "utun0",
            "utun4",
            "bridge100",
            "vmnet1",
            "awdl0",
            "anpi2",
            "LIMA0",
        ] {
            assert!(is_virtual_mac_interface(name), "{name}");
        }
        for name in ["en0", "en5", "eth0", "lo0", "utun", "bridge"] {
            assert!(!is_virtual_mac_interface(name), "{name}");
        }
    }

    #[test]
    fn select_prefers_default_route_on_reachable_physical() {
        let mut usable = std::collections::HashSet::new();
        usable.insert("en0".to_owned());
        usable.insert("utun3".to_owned());
        let hardware = "Hardware Port: Wi-Fi\nDevice: en0\nHardware Port: VPN\nDevice: utun3\n";
        let route = "   gateway: 192.168.1.1\n  interface: en0\n      flags: <UP>\n";
        let nwi = "IPv4 network interface information\n   en0 : flags 0x1\n   reach : 0x00000002 (Reachable)\n";
        assert_eq!(
            select_physical_interface(route, hardware, nwi, &usable).unwrap(),
            "en0"
        );
    }

    #[test]
    fn select_falls_back_to_first_reachable() {
        let mut usable = std::collections::HashSet::new();
        usable.insert("en1".to_owned());
        let hardware = "Device: en1\n";
        let nwi = "IPv4 network interface information\n   en1 : flags 0x2\n   reach : 0x00000002 (Reachable)\n";
        assert_eq!(
            select_physical_interface("", hardware, nwi, &usable).unwrap(),
            "en1"
        );
    }

    #[test]
    fn select_fails_closed() {
        let usable = std::collections::HashSet::new();
        assert!(select_physical_interface("", "Device: en0\n", "", &usable).is_err());
    }

    #[test]
    fn xml_escaping() {
        assert_eq!(xml_escape("a<b>&\"c\""), "a&lt;b&gt;&amp;&quot;c&quot;");
    }

    #[test]
    fn core_path_is_bundled_only() {
        // In a dev checkout without the bundle, this must fail closed with a
        // pointer to the fetch script.
        let err = core_path().unwrap_err();
        assert!(err.contains("fetch-proxy-core.sh") || err.contains("重新安装"));
    }
}
