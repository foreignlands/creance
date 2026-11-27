use super::*;

fn status_json(s: &GateStatus) -> Vec<u8> {
    serde_json::to_vec(s).unwrap_or_else(|_| error_json("status serialize failed"))
}

impl Gate {
    /// Starts a gate: creates the record in `instance_dir` (socket path,
    /// token, run id) and spawns the control server. The returned handle
    /// owns the gate's lifetime — dropping it stops the server and removes
    /// the socket directory.
    pub fn start(
        instance_dir: &str,
        config_path: &str,
        profile_dir: &str,
        instance: &str,
        proxy_port: u16,
    ) -> Result<GateHandle, String> {
        let token = creance_proxy::token();
        let run_id = creance_proxy::token()[..32].to_owned();
        let sock_dir =
            std::env::temp_dir().join(format!("gate-{}", creance_proxy::token()[..8].to_owned()));
        creance_vm::private::ensure_private_dir(sock_dir.to_string_lossy().as_ref())
            .map_err(|e| e.to_string())?;
        let socket = sock_dir.join("control.sock").to_string_lossy().into_owned();
        let _ = std::fs::remove_file(&socket);
        let listener = UnixListener::bind(&socket).map_err(|e| e.to_string())?;
        creance_vm::private::protect_file(&socket).map_err(|e| e.to_string())?;
        // Guest 认证桥：loopback TCP 控制口，由 ssh -R 转进 guest——
        // restrict=on 下仍走 ssh 信道，guest 持 token 才能调用。
        let tcp = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .map_err(|e| e.to_string())?;
        let tcp_port = tcp.local_addr().map_err(|e| e.to_string())?.port();

        let record = GateRecord {
            socket: socket.clone(),
            token: token.clone(),
            run_id: run_id.clone(),
            tcp_port,
        };
        // Publish the record atomically; readers check it is private.
        let bytes = serde_json::to_vec_pretty(&record).map_err(|e| e.to_string())?;
        let record_path = Path::new(instance_dir).join("cage-gate.json");
        let tmp = Path::new(instance_dir)
            .join(format!(".gate-{}", creance_proxy::token()[..8].to_owned()));
        std::fs::write(&tmp, &bytes).map_err(|e| e.to_string())?;
        creance_vm::private::protect_file(tmp.to_string_lossy().as_ref())
            .map_err(|e| e.to_string())?;
        std::fs::rename(&tmp, &record_path).map_err(|e| {
            let _ = std::fs::remove_file(&tmp);
            e.to_string()
        })?;

        // Own-wire dataplane: the instance record's hw_cid selects vsock
        // over ssh -R. Lima/macOS and legacy records read 0.
        #[cfg(target_os = "linux")]
        let hw_cid = creance_vm::qemu::load_hw(profile_dir, instance)
            .map(|h| h.cid)
            .unwrap_or(0);
        #[cfg(not(target_os = "linux"))]
        let hw_cid: u32 = 0;

        let gate = Arc::new(Gate {
            profile_dir: profile_dir.to_owned(),
            instance: instance.to_owned(),
            proxy_port,
            run_id,
            token,
            inner: Mutex::new(GateInner {
                state: GateState::Closed,
                reason: String::new(),
                epoch: 0,
                opened_at: None,
                lease: CHECK_LEASE,
                report: None,
                check_id: String::new(),
                counts: std::collections::BTreeMap::new(),
                recorded: config::load(config_path).ok(),
            }),
            shutdown: AtomicBool::new(false),
            config_path: config_path.to_owned(),
            record_path: record_path.to_string_lossy().into_owned(),
            socket_path: socket.clone(),
            listener: Mutex::new(Some(listener)),
            tcp_listener: Mutex::new(Some(tcp)),
            tcp_port,
            evidence: Mutex::new(EvidenceState::default()),
            hw_cid,
            vbridge: Mutex::new(None),
            cbridge: Mutex::new(None),
        });

        // The lease watchdog: a gate left open (or checking) without renewal
        // closes itself with a fixed reason. It holds only a Weak reference
        // so a dropped handle fully retires the gate.
        let watchdog = Arc::downgrade(&gate);
        std::thread::spawn(move || {
            // 0.6.x 常驻巡检/自动熔断：在闸开着的每个 tick 采样核心存活
            // （loopback TCP connect 到托管核心监听）。连续 FUSE_TICKS 个
            // tick（≈1.5s）不可达 → 熔断关闸；closed 分支下一个 tick 把
            // wire 切断——端到端 ≤2s。零泄漏由 guest 侧 iptables 兜底
            // （guest 本就只有 NAT 主机白名单 + 隧道一条路）。
            let mut core_down_ticks = 0u32;
            // ~30s at the 500ms tick: interval between exit-evidence
            // samples while the gate is Open.
            let mut evidence_ticks = 0u32;
            let mut gate_sync_ticks = 0u32;
            let mut wire_sync_ticks = 0u32;
            loop {
                std::thread::sleep(Duration::from_millis(500));
                let Some(watchdog) = watchdog.upgrade() else {
                    return;
                };
                if watchdog.shutdown.load(Ordering::Relaxed) {
                    return;
                }
                let mut inner = lock_or_recover(&watchdog.inner);
                if let (Some(opened), lease) = (inner.opened_at, inner.lease)
                    && opened.elapsed() > lease
                {
                    inner.close("检测租期到期，等待重新检查");
                }
                // 0.4: the VM's wire follows the gate. Closed gate → the ssh -R
                // tunnel must be down; Open/Checking → it must be up. Healing is
                // one-way (we cut, we do not silently re-raise). Reaping backs
                // the stop with a signature sweep so the cut holds even when the
                // pid file was lost (F-026). Only the canonical daemon moves the
                // wire (F-028): a renamed-over loser must neither cut nor raise
                // what the winner owns — its main loop retires it within a tick.
                let closed = inner.state == GateState::Closed;
                let open = inner.state == GateState::Open;
                drop(inner);
                if !watchdog.still_owner() {
                    continue;
                }
                // Guest 认证桥不是 egress——daemon 活着就转发（gate
                // Closed 时 guest 仍可调白名单插件），只随 daemon 死。
                if watchdog.tcp_port != 0 {
                    // Control plane over vsock (host-channel hygiene): a
                    // second AF_VSOCK bridge on the daemon's tcp_port
                    // replaces the permanent gatebridge ssh -R — no
                    // long-lived forwarding process left in the host's
                    // ps. ssh -R remains the fallback when the host has
                    // no vhost-vsock, and for legacy/macOS instances.
                    let cbridged = if watchdog.hw_cid != 0 {
                        {
                            let mut cb = lock_or_recover(&watchdog.cbridge);
                            if cb.is_none() {
                                match super::vsock::VsockBridge::start(watchdog.tcp_port) {
                                    Ok(b) => {
                                        *cb = Some(b);
                                        let _ = creance_vm::tunnel::stop_named(
                                            &watchdog.profile_dir,
                                            "gatebridge",
                                        );
                                    }
                                    Err(_) => {
                                        let _ = creance_vm::tunnel::ensure_named(
                                            &watchdog.profile_dir,
                                            &watchdog.instance,
                                            watchdog.tcp_port,
                                            "gatebridge",
                                        );
                                    }
                                }
                            }
                            cb.is_some()
                        }
                    } else {
                        let _ = creance_vm::tunnel::ensure_named(
                            &watchdog.profile_dir,
                            &watchdog.instance,
                            watchdog.tcp_port,
                            "gatebridge",
                        );
                        false
                    };
                    // `~/.creance-gate` goes stale whenever a NEW record
                    // supersedes the one `up` synced (fresh tcp_port +
                    // token — e.g. daemon restarted without `up`). Push
                    // the material once per record content; the marker
                    // tracks what actually landed guest-side. Retried
                    // every ~10s — a powered-off guest fails fast.
                    gate_sync_ticks += 1;
                    let marker = Path::new(&watchdog.record_path)
                        .parent()
                        .map(|p| p.join(".gate-synced"));
                    let expected = format!("{}:{}", watchdog.tcp_port, watchdog.token);
                    if let Some(marker) = marker {
                        let synced = std::fs::read_to_string(&marker)
                            .map(|m| m.trim() == expected)
                            .unwrap_or(false);
                        if !synced && gate_sync_ticks >= 20 {
                            gate_sync_ticks = 0;
                            // The forwarder restart rides along ONLY when
                            // the control plane is actually on vsock — in
                            // the ssh -R fallback the guest port already
                            // belongs to the tunnel and a competing socat
                            // bind would fight it (F-A1's shape on the
                            // control wire). The same predicate pushes the
                            // ~/.creance-vsock marker the unit's second
                            // ConditionPathExists arms on (M-A4: systemd
                            // re-fires enabled units at boot on its own —
                            // the restart guard alone could not stop a
                            // fallback-path boot trigger); a stale marker
                            // is swept on the fallback write.
                            let restart = if cbridged {
                                "; touch \"$HOME/.creance-vsock\"; systemctl --user restart creance-gatewire 2>/dev/null || true"
                            } else {
                                // Fallback: sweep the marker AND stop a
                                // unit a stale marker may already have
                                // fired this boot — a running socat
                                // ignores later file deletes and would
                                // hold its stale port until reboot.
                                "; rm -f \"$HOME/.creance-vsock\"; systemctl --user stop creance-gatewire 2>/dev/null || true"
                            };
                            if creance_vm::vm::guest_script(
                                &watchdog.profile_dir,
                                &watchdog.instance,
                                &format!(
                                    "umask 077; printf '%s\\n%s\\n' '{}' '{}' > \"$HOME/.creance-gate\"{restart}",

                                    watchdog.tcp_port, watchdog.token
                                ),
                            )
                            .is_ok()
                            {
                                let _ = std::fs::write(&marker, &expected);
                            }
                        }
                    }
                }
                if closed {
                    let _ = creance_vm::tunnel::stop(&watchdog.profile_dir);
                    creance_vm::tunnel::reap_orphans(
                        &watchdog.profile_dir,
                        &watchdog.instance,
                        watchdog.proxy_port,
                    );
                    // Own-wire cut: dropping the bridge closes the
                    // listener and every live splice (stop flag, quarter-
                    // second poll granularity).
                    lock_or_recover(&watchdog.vbridge).take();
                } else if watchdog.hw_cid != 0 {
                    // Own-wire dataplane (hw_cid > 0): the AF_VSOCK
                    // bridge, with the ssh -R tunnel as the recorded
                    // fallback when the host lacks /dev/vhost-vsock.
                    let bridge_active = {
                        let mut vb = lock_or_recover(&watchdog.vbridge);
                        if vb.is_none() {
                            match super::vsock::VsockBridge::start(watchdog.proxy_port) {
                                Ok(b) => {
                                    *vb = Some(b);
                                    // The ssh -R fallback may have served
                                    // earlier ticks of THIS open session —
                                    // retire it so the guest port belongs to
                                    // the own-wire forwarder alone (the
                                    // unit's Restart=always heals the brief
                                    // teardown race). A no-op when the
                                    // fallback never ran.
                                    let _ = creance_vm::tunnel::stop(&watchdog.profile_dir);
                                }
                                Err(_) => {
                                    let _ = creance_vm::tunnel::ensure(
                                        &watchdog.profile_dir,
                                        &watchdog.instance,
                                        watchdog.proxy_port,
                                    );
                                }
                            }
                        }
                        vb.is_some()
                    };
                    // Guest forwarder material: the user unit's env file
                    // (~/.creance-wire = PORT=…) pushed like .creance-gate,
                    // throttled, marked .wire-synced on success. Only when
                    // the bridge is actually serving: the ssh -R fallback
                    // already lands the port inside the guest, and a socat
                    // bind on the same port would fight it (F-A1).
                    if bridge_active {
                        wire_sync_ticks += 1;
                        let marker = Path::new(&watchdog.record_path)
                            .parent()
                            .map(|p| p.join(".wire-synced"));
                        let expected = format!("PORT={}", watchdog.proxy_port);
                        if let Some(marker) = marker {
                            let synced = std::fs::read_to_string(&marker)
                                .map(|m| m.trim() == expected)
                                .unwrap_or(false);
                            if !synced && wire_sync_ticks >= 20 {
                                wire_sync_ticks = 0;
                                if creance_vm::vm::guest_script(
                                    &watchdog.profile_dir,
                                    &watchdog.instance,
                                    &format!(
                                        "umask 077; printf 'PORT=%s\\n' '{}' > \"$HOME/.creance-wire\"; systemctl --user restart creance-wire 2>/dev/null || true",
                                        watchdog.proxy_port
                                    ),
                                )
                                .is_ok()
                                {
                                    let _ = std::fs::write(&marker, &expected);
                                }
                            }
                        }
                    }
                } else {
                    let _ = creance_vm::tunnel::ensure(
                        &watchdog.profile_dir,
                        &watchdog.instance,
                        watchdog.proxy_port,
                    );
                }
                if !closed {
                    // 熔断采样：连接被拒瞬间返回（常见死核心形态）；一个
                    // 存活监听则每 tick 清零计数。只在 Open 态计数——
                    // Checking 有自己的租期，不在此误熔断启动竞态。
                    let core_up = !open
                        || std::net::TcpStream::connect_timeout(
                            &std::net::SocketAddr::from(([127, 0, 0, 1], watchdog.proxy_port)),
                            Duration::from_millis(250),
                        )
                        .is_ok();
                    if core_up {
                        core_down_ticks = 0;
                    } else {
                        core_down_ticks += 1;
                        if core_down_ticks >= 3 {
                            lock_or_recover(&watchdog.inner).close("代理核心不可达，自动熔断");
                            core_down_ticks = 0;
                        }
                    }
                }
                // 出口证据采样（0.6.6 后半）：Open 态下周期性经托管核心
                // 抓 trace——国别与授权时观测漂移（节点被换/订阅重路由）
                // → 熔断关闸。采样在独立线程，10s 预算，不阻塞熔断与租期
                // 判定；失败只计数，上游抖动不定罪。授权时无国别基线
                // （旧报告/无观测）则跳过。
                if open {
                    evidence_ticks += 1;
                    let mut ev = lock_or_recover(&watchdog.evidence);
                    if let Some(result) = ev.result.take() {
                        ev.in_flight = false;
                        let mut inner = lock_or_recover(&watchdog.inner);
                        match result {
                            Ok((sample, corroborated)) => {
                                if let Some(reason) =
                                    evidence_verdict(inner.report.as_ref(), &sample)
                                {
                                    inner.close(&reason);
                                } else {
                                    let base_ip = inner
                                        .report
                                        .as_ref()
                                        .and_then(|r| r.checks.get("exit_ip"))
                                        .cloned()
                                        .unwrap_or_default();
                                    if !base_ip.is_empty() && sample.ip != base_ip {
                                        *inner
                                            .counts
                                            .entry("exit_ip_drift".to_owned())
                                            .or_default() += 1;
                                    }
                                    // F-038 narrowing in the verdict path:
                                    // the grant-time baseline corroborated
                                    // but the live sample does not — the
                                    // second source going silent (or
                                    // starting to disagree) is counted,
                                    // never convicted: ipinfo availability
                                    // is not evidence of laundering.
                                    let base_corrob = inner
                                        .report
                                        .as_ref()
                                        .and_then(|r| r.checks.get("exit_corroborated"))
                                        .map(String::as_str)
                                        .unwrap_or_default();
                                    if base_corrob == "yes" && !corroborated {
                                        *inner
                                            .counts
                                            .entry("exit_corrob_lost".to_owned())
                                            .or_default() += 1;
                                    }
                                }
                            }
                            Err(_) => {
                                *inner
                                    .counts
                                    .entry("exit_sample_failed".to_owned())
                                    .or_default() += 1;
                            }
                        }
                    }
                    let has_baseline = lock_or_recover(&watchdog.inner)
                        .report
                        .as_ref()
                        .and_then(|r| r.checks.get("exit_country"))
                        .map(|c| !c.is_empty())
                        .unwrap_or(false);
                    if evidence_ticks >= 60 && !ev.in_flight && has_baseline {
                        evidence_ticks = 0;
                        ev.in_flight = true;
                        drop(ev);
                        let weak = Arc::downgrade(&watchdog);
                        std::thread::spawn(move || {
                            if let Some(g) = weak.upgrade() {
                                let result = config::load(&g.config_path).and_then(|cfg| {
                                    cfg.resolved_proxy_url()
                                        .and_then(|u| {
                                            creance_net::egress::Egress::new(&u, &cfg.dns_url)
                                        })
                                        .and_then(|e| {
                                            creance_net::trace::sample_pair(
                                                &e,
                                                Instant::now() + Duration::from_secs(10),
                                            )
                                        })
                                });
                                lock_or_recover(&g.evidence).result = Some(result);
                            }
                        });
                    }
                }
            }
        });

        // The accept loops also hold only a Weak: they exit when the gate
        // is dropped or shut down; the unix loop owns socket-file cleanup.
        let accept_sock = socket.clone();
        let accept_dir = sock_dir.to_string_lossy().into_owned();
        let server = Arc::downgrade(&gate);
        std::thread::spawn(move || {
            loop {
                let Some(server) = server.upgrade() else {
                    break;
                };
                if server.shutdown.load(Ordering::Relaxed) {
                    break;
                }
                // Accept on the listener the Gate still owns; taking it in
                // shutdown() drops the fd and unblocks us with an error.
                let accepted = {
                    let guard = lock_or_recover(&server.listener);
                    match guard.as_ref() {
                        Some(listener) => listener.accept().map(|(s, _)| s),
                        None => Err(std::io::Error::other("gate closed")),
                    }
                };
                match accepted {
                    Ok(stream) => {
                        let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
                        let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
                        let server = server.clone();
                        std::thread::spawn(move || server.handle(stream, false));
                    }
                    Err(_) => {
                        if server.shutdown.load(Ordering::Relaxed) {
                            break;
                        }
                        // Transient accept errors (EMFILE, ECONNABORTED):
                        // back off instead of spinning.
                        std::thread::sleep(Duration::from_millis(50));
                    }
                }
                drop(server);
            }
            let _ = std::fs::remove_file(&accept_sock);
            let _ = std::fs::remove_dir(&accept_dir);
        });
        // TCP bridge accept loop — same protocol, same auth, different
        // transport (the guest reaches it over ssh -R).
        let server = Arc::downgrade(&gate);
        std::thread::spawn(move || {
            loop {
                let Some(server) = server.upgrade() else {
                    break;
                };
                if server.shutdown.load(Ordering::Relaxed) {
                    break;
                }
                let accepted = {
                    let guard = lock_or_recover(&server.tcp_listener);
                    match guard.as_ref() {
                        Some(listener) => listener.accept().map(|(s, _)| s),
                        None => Err(std::io::Error::other("gate closed")),
                    }
                };
                match accepted {
                    Ok(stream) => {
                        let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
                        let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
                        let server = server.clone();
                        std::thread::spawn(move || server.handle(stream, true));
                    }
                    Err(_) => {
                        if server.shutdown.load(Ordering::Relaxed) {
                            break;
                        }
                        std::thread::sleep(Duration::from_millis(50));
                    }
                }
                drop(server);
            }
        });
        Ok(GateHandle {
            gate,
            record,
            instance_dir: instance_dir.to_owned(),
            owns_record: AtomicBool::new(true),
        })
    }

    /// Stops the server loop and closes the listening socket. The accept
    /// thread removes the socket directory on its way out.
    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::Relaxed);
        // Dropping our listener fd alone leaves the accept thread's view
        // open (fds are references); a self-connect wakes it so it observes
        // the flag and exits.
        if let Ok(mut guard) = self.listener.try_lock() {
            *guard = None;
        }
        if let Ok(mut guard) = self.tcp_listener.try_lock() {
            *guard = None;
        }
        let _ = std::os::unix::net::UnixStream::connect(&self.socket_path);
        let _ = std::net::TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, self.tcp_port));
    }

    /// The current status snapshot.
    pub fn status(&self) -> GateStatus {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .status(&self.run_id)
    }

    /// Whether the published record still names THIS gate (F-028). A daemon
    /// renamed over by a successor must not touch the wire; when in doubt
    /// (unreadable record), it also holds back — the main loop decides.
    pub(crate) fn still_owner(&self) -> bool {
        std::fs::read(&self.record_path)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<GateRecord>(&bytes).ok())
            .is_some_and(|record| record.run_id == self.run_id)
    }

    /// Serves one request. `guest` callers (the TCP bridge) may only
    /// read status and invoke plugins — check/grant/close stay unix-only
    /// so the guest bearer can never drive the gate open itself.
    fn handle<S: std::io::Read + std::io::Write>(&self, stream: S, guest: bool) {
        let (head, mut stream) = match creance_net::wire::read_header_block(stream, 16 << 10) {
            Ok((h, r)) if !h.is_empty() => (h, r),
            _ => return,
        };
        let (request_line, fields) = creance_net::wire::parse_header_block(&head);
        let mut parts = request_line.split_whitespace();
        let method = parts.next().unwrap_or_default().to_owned();
        let path = parts.next().unwrap_or_default().to_owned();
        // FINDING-006: invalid or repeated Content-Length is an ambiguity
        // smuggling vector — refuse it.
        let body_len = match creance_net::wire::strict_content_length(&fields) {
            Ok(Some(n)) => n,
            Ok(None) => 0,
            Err(_) => {
                let _ = stream.write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n");
                return;
            }
        };
        let mut bearer = String::new();
        let mut host = String::new();
        let mut origin_present = false;
        for (k, v) in &fields {
            if k.eq_ignore_ascii_case("authorization") {
                bearer = v.strip_prefix("Bearer ").unwrap_or_default().to_owned();
            } else if k.eq_ignore_ascii_case("host") {
                host = v.clone();
            } else if k.eq_ignore_ascii_case("origin") {
                origin_present = true;
            }
        }
        // Host must be the private name, Origin must be absent, and the
        // bearer must match the record's token.
        if host != "gate"
            || origin_present
            || !constant_time_eq(bearer.as_bytes(), self.token.as_bytes())
        {
            let _ = stream.write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n");
            return;
        }
        if body_len > 64 << 10 {
            let _ = stream.write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n");
            return;
        }
        let mut body = vec![0u8; body_len];
        if body_len > 0 && stream.read_exact(&mut body).is_err() {
            return;
        }
        if guest && !(method == "GET" && path == "/status") {
            let allowed = method == "POST"
                && path == "/control"
                && serde_json::from_slice::<GateCommand>(&body)
                    .map(|c| c.action == "plugin")
                    .unwrap_or(false);
            if !allowed {
                let _ = stream.write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n");
                return;
            }
        }
        let response = match (method.as_str(), path.as_str()) {
            ("GET", "/status") => {
                let status = status_json(&self.status());
                (200, status)
            }
            ("POST", "/control") => self.control(&body),
            _ => (404, error_json("not found")),
        };
        let _ = stream.write_all(
            format!(
                "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                response.0,
                reason(response.0),
                response.1.len()
            )
            .as_bytes(),
        );
        let _ = stream.write_all(&response.1);
    }

    fn control(&self, body: &[u8]) -> (u16, Vec<u8>) {
        let mut command: GateCommand = match serde_json::from_slice(body) {
            Ok(c) => c,
            Err(e) => return (400, error_json(&format!("invalid command: {e}"))),
        };
        // Every mutating action first re-validates the applied proxy.
        let config = match config::load(&self.config_path) {
            Ok(c) => c,
            Err(_) => {
                lock_or_recover(&self.inner).close("配置读取失败，外网保持关闭");
                return (409, error_json("配置读取失败，外网保持关闭"));
            }
        };
        // 插件调用=微型 gate-open：白名单+批条纪律（plugin.rs），属宿主侧
        // 操作，不做出口动作——放在 applied-proxy 复检之前，也不触碰闸态。
        if command.action == "plugin" {
            let configured =
                !(config.approval_bot_token.is_empty() && config.approval_chat_id.is_empty());
            return match crate::gate::plugin::call(
                &self.profile_dir,
                configured,
                &command.plugin,
                &command.args,
            ) {
                Ok(v) => (
                    200,
                    serde_json::to_vec(&v).unwrap_or_else(|_| b"{}".to_vec()),
                ),
                Err(e) => (403, error_json(&e)),
            };
        }
        if let Err(e) = creance_proxy::applied(
            Path::new(&self.config_path)
                .parent()
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_default()
                .as_str(),
            &config.proxy_url,
            &config.proxy_revision,
        ) {
            lock_or_recover(&self.inner).close(&format!("代理节点未应用：{e}"));
            return (409, error_json(&format!("代理节点未应用：{e}")));
        }
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.status(&self.run_id); // keep the counts shape warm
        match command.action.as_str() {
            "check" => {
                inner.state = GateState::Checking;
                inner.reason.clear();
                inner.opened_at = Some(Instant::now());
                inner.lease = CHECK_LEASE;
                // FINDING-008: the check window gets an id; a grant must
                // carry it back, tying the report to this window (Go's
                // CheckID binding).
                inner.check_id = creance_vm::token()[..16].to_owned();
                (200, status_json(&inner.status(&self.run_id)))
            }
            "fault" => {
                // Fault injection only stands during checking; it closes the gate.
                inner.close("注入故障演练，外网保持关闭");
                (200, status_json(&inner.status(&self.run_id)))
            }
            "grant" => {
                // FINDING-008: Go only grants from the Checking state with
                // the report bound to the open check window. F-036 adds
                // the run binding: the report must name THIS gate's run
                // and be minted inside the check window, and the inner
                // report id must match the outer one (they used to be
                // checked asymmetrically).
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                let window = CHECK_LEASE.as_secs();
                let bound = |report: &SafetyReport| {
                    report.run_id == self.run_id
                        && report.created_at <= now
                        && now - report.created_at <= window
                };
                if inner.state != GateState::Checking {
                    (409, error_json("仅在检测进行中可以授权开放，外网保持关闭"))
                } else if command.report_id != inner.check_id || inner.check_id.is_empty() {
                    inner.close("授权与当前检测窗口不匹配，外网保持关闭");
                    (409, error_json("授权与当前检测窗口不匹配，外网保持关闭"))
                } else {
                    match command.report.take() {
                        Some(report)
                            if report.authorizes()
                                && report.report_id == command.report_id
                                && bound(&report) =>
                        {
                            inner.state = GateState::Open;
                            inner.reason.clear();
                            inner.opened_at = Some(Instant::now());
                            inner.lease = OPEN_LEASE;
                            inner.report = Some(report);
                            (200, status_json(&inner.status(&self.run_id)))
                        }
                        _ => (409, error_json("安全报告缺失必需的通过项，外网保持关闭")),
                    }
                }
            }
            "renew" => {
                let matches_report = inner
                    .report
                    .as_ref()
                    .map(|r| r.report_id == command.report_id)
                    .unwrap_or(false);
                if inner.state == GateState::Open && matches_report {
                    inner.opened_at = Some(Instant::now());
                    (200, status_json(&inner.status(&self.run_id)))
                } else {
                    inner.close("续期与当前检测不匹配，外网保持关闭");
                    (409, error_json("续期与当前检测不匹配"))
                }
            }
            "close" => {
                inner.close(if command.reason.is_empty() {
                    "收到关闭指令，外网保持关闭"
                } else {
                    &command.reason
                });
                (200, status_json(&inner.status(&self.run_id)))
            }
            "proxy-revision" => match self.sync_proxy_revision_with(&mut inner) {
                // F-036: only an ADOPTED change (or a rejected sync) closes
                // the gate — an idempotent no-change sync keeps the state,
                // so a routine `proxy-start` on an unchanged config no
                // longer force-retires an open gate.
                Ok(SyncOutcome::Adopted) => {
                    inner.close("代理节点已变更，等待重新检查");
                    (200, status_json(&inner.status(&self.run_id)))
                }
                Ok(SyncOutcome::Unchanged) => (200, status_json(&inner.status(&self.run_id))),
                Err(message) => {
                    inner.close(&message);
                    (409, error_json(&message))
                }
            },
            _ => (400, error_json("unknown action")),
        }
    }

    /// Adopts a changed exit, comparing the freshly loaded config against
    /// the snapshot this gate started with. A pure revision change — or a
    /// first-time completion of the exit-policy binding under the same mode
    /// and scope — is accepted and recorded; anything else requires a
    /// restart. No change is an idempotent success.
    fn sync_proxy_revision_with(&self, inner: &mut GateInner) -> Result<SyncOutcome, String> {
        let new_config = config::load(&self.config_path)?;
        let old_config = inner
            .recorded
            .clone()
            .ok_or("出口地址或环境设置变化需要重启环境".to_owned())?;
        let revision_changed = new_config.proxy_revision != old_config.proxy_revision
            || new_config.proxy_url != old_config.proxy_url;
        let binding_completed = old_config.exit_policy.needs_binding()
            && new_config.exit_policy.normalized().mode == old_config.exit_policy.normalized().mode
            && new_config.exit_policy.normalized().scope
                == old_config.exit_policy.normalized().scope
            && !new_config.exit_policy.needs_binding();
        if !revision_changed && !binding_completed {
            // Nothing to adopt: the gate keeps its state. F-041: the
            // anchor is part of "nothing" — strip_config removes
            // exit_policy, so an anchor change with a still revision
            // used to sail through here as Unchanged while the open gate
            // kept evidence judged against the OLD anchor. Only a
            // bitwise-identical anchor counts as unchanged; anything
            // else demands a restart.
            if strip_config(&old_config) == strip_config(&new_config)
                && old_config.exit_policy.normalized() == new_config.exit_policy.normalized()
            {
                return Ok(SyncOutcome::Unchanged);
            }
            return Err("出口地址或环境设置变化需要重启环境".to_owned());
        }
        if strip_config(&old_config) != strip_config(&new_config) {
            return Err("出口地址或环境设置变化需要重启环境".to_owned());
        }
        // FINDING-008: the exit policy may only be *completed*, never
        // modified — Go's SyncProxyRevision allows each field to change
        // only from unbound to a value. Any other change demands a restart.
        if !exit_policy_only_completed(&old_config.exit_policy, &new_config.exit_policy) {
            return Err("出口地址或环境设置变化需要重启环境".to_owned());
        }
        if new_config.proxy_revision.is_empty() {
            return Err("出口地址或环境设置变化需要重启环境".to_owned());
        }
        inner.recorded = Some(new_config.clone());
        // Go refreshes the environment's running record so its fingerprint
        // matches the adopted configuration.
        let instance_dir = Path::new(&self.record_path)
            .parent()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default();
        let _ = creance_vm::running::record_running(&instance_dir, &new_config);
        Ok(SyncOutcome::Adopted)
    }
}

/// What a proxy-revision sync decided (F-036): an adopted change closes
/// the gate for re-checking; an idempotent no-change keeps the state.
enum SyncOutcome {
    Adopted,
    Unchanged,
}

/// True when `new` only fills fields `old` left empty (same mode/scope);
/// any bound value that changed means the anchor moved — a restart.
fn exit_policy_only_completed(
    old: &crate::exit_policy::Policy,
    new: &crate::exit_policy::Policy,
) -> bool {
    let old = old.normalized();
    let new = new.normalized();
    if old.mode != new.mode || old.scope != new.scope {
        return false;
    }
    let completed = |o: &str, n: &str| o.is_empty() || o == n;
    completed(&old.ip, &new.ip)
        && completed(&old.country_code, &new.country_code)
        && completed(&old.region, &new.region)
        && completed(&old.city, &new.city)
}

/// The fields a revision change may move: the exit endpoint/revision and the
/// exit-policy binding. Everything else must match for a sync to be adopted.
fn strip_config(c: &Config) -> Config {
    let mut c = c.clone();
    c.exit_policy = Default::default();
    c.proxy_url = String::new();
    c.proxy_revision = String::new();
    c
}
