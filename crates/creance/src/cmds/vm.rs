use super::*;
use creance::escape;
use creance_gate::gate;
use creance_net::egress::Egress;
use creance_vm::running;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::time::Instant;

pub(crate) fn cmd_init() -> i32 {
    let path = config::config_path();
    let parent = Path::new(&path)
        .parent()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|| ".".to_owned());
    if let Err(e) = creance_vm::private::ensure_private_dir(&parent) {
        return fail(e.to_string());
    }
    // 防越权层：安装期属主绑定——记录创建者 uid，越权者拿着目录也
    // 会被 access-owner-bound 探针判离。
    let _ = creance_vm::private::record_owner(&parent);
    let bytes = match serde_json::to_vec_pretty(&config::default_config()) {
        Ok(b) => b,
        Err(e) => return fail(e.to_string()),
    };
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
    {
        Ok(mut f) => {
            use std::io::Write;
            if let Err(e) = f.write_all(&bytes) {
                return fail(e.to_string());
            }
            println!("Profile created: {path}");
            0
        }
        Err(e) => fail(e.to_string()),
    }
}

pub(crate) fn cmd_check() -> i32 {
    let path = config::config_path();
    let cfg = match config::load(&path) {
        Ok(c) => c,
        Err(e) => return fail(e),
    };
    let egress = match Egress::new(&cfg.proxy_url, &cfg.dns_url) {
        Ok(e) => e,
        Err(e) => return fail(e),
    };
    match creance_net::egress::request(
        &egress,
        "GET",
        CHECK_URL,
        None,
        &[],
        Instant::now() + CHECK_BUDGET,
    ) {
        Ok(r) if r.status == 200 => {
            println!("Proxy transport OK. Guest traffic still requires VM acceptance checks.");
            0
        }
        Ok(r) => fail(format!("proxy check returned HTTP {}", r.status)),
        Err(_) => fail("proxy transport check failed (no direct fallback)".to_owned()),
    }
}

pub(crate) fn cmd_gate(open: bool) -> i32 {
    let profile = profile();
    let instance = instance();
    let instance_dir =
        creance_vm::paths::join(&creance_vm::vm::instances_root(&profile), &instance);
    let outcome = if open {
        // 0.5: a grant needs live exit evidence. Observe the exit through
        // the configured proxy, evaluate it against the anchor (plus the
        // mandatory mainland deny list), and only a Passed verdict opens
        // the wire — anything else stays closed with the reason.
        let cfg = match config::load(&config::config_path()) {
            Ok(c) => c,
            Err(e) => return fail(e),
        };
        // F-042: the core's unix controller ignores the configured secret
        // (live-verified), so a flipped core (mode=direct, a MATCH,DIRECT
        // reload) would feed the evidence sample whatever the flipper
        // wants. Reconcile the running core against its generated config
        // first — a diverged core may not supply exit evidence.
        // F-050: a store that cannot be read is not a reason to skip the
        // reconciliation — corrupting sources.json used to blind both
        // checks at once. Gate-open is a safety-sensitive path: no store,
        // no evidence.
        match creance_proxy::load(&profile) {
            Ok(store) => {
                if let Err(e) = creance_proxy::service::check_running(&profile, &store) {
                    return fail(format!(
                        "核心运行态已偏离配置（{e}），拒绝采样出口证据，外网保持关闭"
                    ));
                }
            }
            Err(e) => return fail(format!("代理配置不可读，拒绝采样出口证据：{e}")),
        }
        let location = match creance::evidence::observe(&cfg) {
            Ok(l) => l,
            Err(e) => return fail(format!("出口观测失败，外网保持关闭：{e}")),
        };
        // F-046: reconcile AGAIN after the sample — a core flipped inside
        // the check→observe window cannot have supplied the evidence. The
        // residual window shrinks to the milliseconds between sample and
        // this check.
        match creance_proxy::load(&profile) {
            Ok(store) => {
                if let Err(e) = creance_proxy::service::check_running(&profile, &store) {
                    return fail(format!(
                        "核心运行态已偏离配置（{e}），拒绝采样出口证据，外网保持关闭"
                    ));
                }
            }
            Err(e) => return fail(format!("代理配置不可读，拒绝采样出口证据：{e}")),
        }
        let (state, message) = cfg.exit_policy.evaluate(&location.ip, Some(&location));
        if state != creance_vm::exit_policy::State::Passed {
            return fail(format!(
                "出口证据未通过，外网保持关闭：{message}（实测出口 {} {}）",
                location.ip, location.country_code
            ));
        }
        // 四元组一致性（0.7.0）：出口国别已实测——persona 的
        // 时区/语言/locale 落在该地区 plausible 集之外即"US IP + 东八区 +
        // 中文"式穿帮，fail-closed。未登记国别无判词（unknown 不定罪）。
        if let Some(Err(reason)) = creance_vm::exit_policy::fingerprint_verdict(
            &location.country_code,
            &cfg.timezone,
            &cfg.locale,
            &cfg.browser_language,
        ) {
            return fail(format!(
                "出口指纹四元组穿帮，外网保持关闭：{reason}（实测出口 {} {}）",
                location.ip, location.country_code
            ));
        }
        // 时区跟随（0.7.x）：实测出口落地后，把该国的规范时区写进 guest
        // ~/.creance-tz——OAuth 通道启动浏览器时优先采用。best-effort：
        // 写不进去不否定这次观测本身。
        if cfg.timezone == "auto" {
            if let Some(zone) = creance_vm::exit_policy::canonical_timezone(&location.country_code)
            {
                let _ = creance_vm::vm::guest_script(
                    &profile,
                    &instance,
                    &format!("printf '%s\\n' '{zone}' > \"${{HOME:-/tmp}}/.creance-tz"),
                );
            }
        }
        gate::open(&instance_dir, &creance::evidence::grant_checks(&location)).map(|s| {
            format!(
                "open (epoch {}，出口 {} {})",
                s.epoch, location.ip, location.country_code
            )
        })
    } else {
        gate::close_and_remove(&profile, &instance_dir, proxy_store_port(&profile))
            .map(|_| "closed".to_owned())
    };
    match outcome {
        Ok(msg) => {
            println!("gate: {msg}");
            0
        }
        Err(e) => fail(e),
    }
}

pub(crate) fn cmd_escape_test() -> i32 {
    let profile = profile();
    let config_path = config::config_path();
    // Host-side probes first: they need no VM.
    let probes = escape::host_probes(&profile, &config_path);
    let mut code = escape::report(&probes);
    // In-guest probes when the environment exists: stage the script and run
    // it through the VM shell. The flag file on the host is the oracle.
    let instance = instance();
    if std::path::Path::new(&creance_vm::vm::instance_marker(&profile, &instance)).exists() {
        let flag = format!("{}.escape-flag", creance_vm::vm::environment_dir(&profile));
        // The flag is the oracle: it must exist on the host for the guest
        // probe to have anything to look for. Without it fs-flag-readable
        // was a vacuous PASS (F-068).
        let store = creance_proxy::load(&profile).ok();
        let guest = creance_vm::guestprofile::Profile::load_or_create(&profile).ok();
        let script = escape::guest_script(
            &flag,
            &store.as_ref().map(|s| s.auth.clone()).unwrap_or_default(),
            store
                .as_ref()
                .map(|s| s.port)
                .unwrap_or(creance_proxy::DEFAULT_PORT),
            &guest.map(|g| g.username).unwrap_or_default(),
        );
        match creance_vm::vm::guest_script(&profile, &instance, &script) {
            Ok(stdout) => {
                // F-062: the transport is under guest control (Ubuntu's
                // patched bash sources ~/.bashrc for non-interactive ssh
                // sessions — rc files can swallow or forge output). A
                // missing probe line is therefore NOT a pass: every probe
                // the script defines must answer, with a known verdict.
                let expected: Vec<&str> = script
                    .lines()
                    .filter_map(|l| {
                        l.split_once("echo \"PROBE ")
                            .and_then(|(_, rest)| rest.split('"').next())
                            // The first token after "PROBE " is the id;
                            // the rest of the literal is the verdict.
                            .and_then(|id| id.split_whitespace().next())
                    })
                    // Only fully literal ids: the socket loop's
                    // `sock-$s` is a parameterized emit site, not a
                    // statically knowable probe name. (F-064 removed
                    // the probe() helper — every probe now emits
                    // literally and lands in this net.)
                    .filter(|id| !id.contains('$'))
                    .collect();
                let mut missing = Vec::new();
                for id in &expected {
                    let answered = stdout
                        .lines()
                        // The answer is the second whitespace token — a
                        // substring match would let `PROBE x` spoof `PROBE xy`.
                        .any(|l| l.split_whitespace().nth(1) == Some(*id));
                    if !answered {
                        missing.push(*id);
                    }
                }
                if !missing.is_empty() {
                    println!(
                        "PROBE transport ESCAPE — 探针行缺失（传输可能被 guest 致盲）：{missing:?}"
                    );
                    code = 1;
                }
                for line in stdout.lines() {
                    println!("{line}");
                    if line.contains(" ESCAPE") {
                        code = 1;
                    }
                }
            }
            Err(e) => eprintln!("cannot run in-guest probes: {e}"),
        }
        // The flag was placed (or attempted) inside guest_script itself;
        // removing it unconditionally is harmless when it never landed.
        let _ = std::fs::remove_file(&flag);
    }
    code
}

pub(crate) fn cmd_setup(memory: u32, cpus: u32) -> i32 {
    let path = config::config_path();
    let cfg = match config::load(&path) {
        Ok(c) => c,
        Err(e) => return fail(e),
    };
    let profile = profile();
    let instance = instance();
    let guest = match creance_vm::guestprofile::Profile::load_or_create(&profile) {
        Ok(g) => g,
        Err(e) => return fail(e),
    };
    let options = creance_vm::vm::SetupOptions {
        memory_gib: memory,
        cpus,
        disk_gib: 24,
        workspace: creance_vm::vm::environment_dir(&profile),
        // "auto" follows the observed exit at gate-open time; the
        // provision-time guest env still needs a concrete IANA name, so
        // the neutral baseline stands in until the first observation.
        timezone: if cfg.timezone == "auto" {
            "Etc/UTC".to_owned()
        } else {
            cfg.timezone.clone()
        },
        locale: cfg.locale.clone(),
        browser_language: cfg.browser_language.clone(),
        guest,
    };
    // 防越权层：既有 profile 首次 setup 时补记属主绑定。
    let _ = creance_vm::private::record_owner(&profile);
    // F-051: setup on an existing instance rebuilds it — the backend's
    // create refuses to touch a live directory, and every "re-run setup"
    // guidance (drift, promise changes) depends on this path existing.
    // The VM disk goes; the host workspace does not.
    if Path::new(&creance_vm::vm::instance_marker(&profile, &instance)).exists() {
        println!("rebuilding existing instance {instance} (VM disk replaced; workspace untouched)");
        let code = creance_vm::vm::delete(&profile, &instance);
        if code != 0 {
            return fail(format!(
                "cannot remove the existing instance {instance}; run `creance stop` first"
            ));
        }
    }
    let code = creance_vm::vm::setup_instance(&profile, &instance, &options);
    if code == 0 {
        // F-033: the fingerprint the VM was promised at creation. The
        // escape probe compares the live config against this snapshot —
        // drift after a config change means the VM and profile disagree
        // (re-run setup after `creance stop` to re-pin).
        let stamp =
            creance_vm::paths::join(&creance_vm::vm::state_dir(&profile), "fingerprint.txt");
        // F-049: a silently missing stamp permanently disarms the drift
        // check — failing to write it fails the setup.
        if let Err(e) = std::fs::write(&stamp, cfg.guest_fingerprint()) {
            return fail(format!("cannot write fingerprint stamp: {e}"));
        }
        println!("instance {instance} created; run `creance up` to start it");
    }
    code
}

pub(crate) fn cmd_stop(keep_proxy: bool) -> i32 {
    let profile = profile();
    let code = creance_vm::vm::stop_vm(&profile, &instance());
    // F-019: the gate retires by its record going away — close over the
    // socket if a daemon still serves, remove the record either way, and
    // cut the tunnel now (close_and_remove does all three).
    let _ = gate::close_and_remove(&profile, &gate_instance_dir(), proxy_store_port(&profile));
    if code == 0 && !keep_proxy {
        let _ = gate::close_gates(&profile);
        return cmd_simple(|| creance_proxy::service::stop(&profile));
    }
    code
}

pub(crate) fn cmd_up() -> i32 {
    let path = config::config_path();
    let cfg = match config::load(&path) {
        Ok(c) => c,
        Err(e) => return fail(e),
    };
    let profile = profile();
    if let Err(e) = running::check_running(&creance_vm::vm::instances_root(&profile), &cfg) {
        return fail(e);
    }
    // F-044/F-052: the stamp records what the guest was provisioned with,
    // and a bare backend start never re-provisions. Any stamp read
    // failure (missing, unreadable, a directory) refuses `up` — a missing
    // stamp used to skip the check, and starting a nonexistent instance
    // must never end in an unprovisioned VM behind a green exit code.
    let stamp = creance_vm::paths::join(&creance_vm::vm::state_dir(&profile), "fingerprint.txt");
    match std::fs::read_to_string(&stamp) {
        Ok(pinned) if pinned.trim() == cfg.guest_fingerprint() => {}
        Ok(_) => {
            return fail(
                "guest 环境（时区/语言）自创建以来已变更，且启动不会重新供给；请先 creance stop 再 creance setup 重建环境"
                    .to_owned(),
            )
        }
        Err(_) => {
            return fail(
                "fingerprint 戳缺失或不可读（应由 creance setup 写入）；拒绝启动，请先 creance stop 再 creance setup 重建环境"
                    .to_owned(),
            )
        }
    }
    let instance = instance();
    // F-052's template trap: only an instance this profile set up may be
    // started — a bare start of an unknown name must refuse, not invent.
    if !Path::new(&creance_vm::vm::instance_marker(&profile, &instance)).exists() {
        return fail(format!(
            "实例 {instance} 不存在（未 setup 或已被删除）；拒绝启动，请先 creance setup"
        ));
    }
    let code = creance_vm::vm::up(&profile, &instance);
    if code == 0 {
        // 0.4: the gate owns the wire now — Closed gate = tunnel down. Raising
        // the daemon raises the tunnel with it; only on daemon failure do we
        // fall back to the unconditional tunnel so the VM stays usable.
        let port = creance_proxy::load(&profile)
            .map(|s| s.port)
            .unwrap_or(creance_proxy::DEFAULT_PORT);
        let instance_dir =
            creance_vm::paths::join(&creance_vm::vm::instances_root(&profile), &instance);
        if let Err(e) = gate::spawn_daemon(&profile, &instance, &path, &instance_dir, port) {
            eprintln!("warning: gate daemon not raised: {e}");
            if let Err(e) = creance_vm::tunnel::ensure(&profile, &instance, port) {
                eprintln!("warning: guest tunnel not established: {e}");
            }
        }
        let _ = running::record_running(&instance_dir, &cfg);
        // F-059's universal guard: whatever the backend did on THIS boot,
        // the guest must not reach the internet directly. Behavior, not
        // artifacts — a missing boot replay (or a backend that stopped
        // replaying) fails `up` loudly instead of shipping an open VM.
        // TCP is the hard gate; ICMP is checked when ping exists (F-060
        // scoped it to the NAT subnets, so external echoes must die).
        //
        // F-062: positive evidence only. The transport (guest login shell
        // sourcing ~/.bashrc on Ubuntu's patched bash) is under guest
        // control — empty or mangled output used to fall through `Ok(_)`
        // as a green light. The PATH reset at the top defeats PATH
        // shadowing of the probe's commands; absolute paths for the rest.
        // (Not defeatable from here: stdout redirection in rc files and
        // interpreter shadowing — the README's honest-boundaries section
        // says so; the host-side gate evidence is the security control.)
        // F-082: the probe runs as the unprivileged guest user — the
        // fw-armed evidence is a root-owned stamp under /run (written
        // by the egress-lock unit from the LIVE ruleset), not an
        // iptables read the guest user cannot perform.
        // F-099/F-100: the whole chain — probe, verdict, sealed token,
        // marker — is ONE call into creance-vm. No `out` exists here to
        // forge, no verdict result to neutralize, and the marker write
        // requires a token only a passing verdict can mint.
        match creance_vm::gateprobe::verify_and_mark(&profile, &instance) {
            Ok(wrote) => {
                if wrote {
                    println!(
                        "供给完成——下次 creance stop && creance up 起 slirp restrict=on 第二道防线生效"
                    );
                }
            }
            Err(e) => return fail(e),
        }
        println!("Environment is up. The guest's only route out is the managed core (`creance escape-test` proves it).");
    }
    code
}

pub(crate) fn cmd_oauth() -> i32 {
    let profile = profile();
    let instance = instance();
    // The channel is an ssh -L forward into the guest's loopback noVNC
    // plus the ephemeral display stack `creance-oauth` runs. Everything
    // tears down when this command exits — nothing outlives the session.
    let target = match creance_vm::vm::ssh_target(&profile, &instance) {
        Ok(t) => t,
        Err(e) => return fail(e),
    };
    // Guest side is fixed 127.0.0.1:6080; the HOST side takes any free
    // loopback port — a fixed one collides with unrelated listeners.
    let local_port = match std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)) {
        Ok(l) => l.local_addr().map(|a| a.port()).unwrap_or(0),
        Err(e) => return fail(format!("cannot allocate a local port: {e}")),
    };
    let mut fwd = std::process::Command::new("ssh");
    creance_vm::vm::apply_ssh_options(&mut fwd, &target);
    let mut child = match fwd
        .arg("-o")
        .arg("StrictHostKeyChecking=yes")
        .arg("-o")
        .arg("ExitOnForwardFailure=yes")
        .arg("-N")
        .arg("-L")
        .arg(format!("127.0.0.1:{local_port}:127.0.0.1:6080"))
        .arg("127.0.0.1")
        .stdin(std::process::Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => return fail(format!("cannot spawn ssh forward: {e}")),
    };
    std::thread::sleep(std::time::Duration::from_millis(500));
    match child.try_wait() {
        Ok(Some(_)) => return fail("ssh forward exited immediately".to_owned()),
        Ok(None) => {}
        Err(e) => return fail(format!("ssh forward: {e}")),
    }
    if let Err(e) =
        creance_vm::vm::guest_script(&profile, &instance, "sh /usr/local/bin/creance-oauth start")
    {
        let _ = child.kill();
        return fail(e);
    }
    println!("OAuth 通道已开：在宿主浏览器打开 http://127.0.0.1:{local_port}/vnc.html");
    println!("完成验证后回车，通道即销毁（X 桌面、浏览器、noVNC 全部回收）");
    let mut line = String::new();
    let _ = std::io::stdin().read_line(&mut line);
    let _ =
        creance_vm::vm::guest_script(&profile, &instance, "sh /usr/local/bin/creance-oauth stop");
    let _ = child.kill();
    let _ = child.wait();
    println!("oauth channel torn down");
    0
}

pub(crate) fn cmd_shell(command: Vec<String>) -> i32 {
    let path = config::config_path();
    let cfg = match config::load(&path) {
        Ok(c) => c,
        Err(e) => return fail(e),
    };
    let profile = profile();
    if let Err(e) = running::check_running(&creance_vm::vm::instances_root(&profile), &cfg) {
        return fail(e);
    }
    let instance = instance();
    let refs: Vec<&str> = command.iter().map(String::as_str).collect();
    creance_vm::vm::shell(&profile, &instance, &refs)
}
