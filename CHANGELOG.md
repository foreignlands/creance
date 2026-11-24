# Changelog

## [0.7.8] — 手机审批通道

- 复用成熟通道规格落地：`creance approve <action>` 经 Telegram Bot 发
  审批请求（含随机回执码），等本人回复该码后在
  `<profile>/.approvals/` 落 10 分钟批条（0600）。Bot 凭据走
  config.json `approval_bot_token` + `approval_chat_id`；API 调用经
  既有代理 egress 栈，宿主机无入站端口。
- 敏感操作接线：`identity-reset` 与 `persona-use` 在通道已配置时须持
  有效批条，否则拒绝并给 `creance approve` 指引；未配置通道默认放行
  （加固项非必须项）。

## [0.7.7] — 2026-11-24

### 新增

- **整机迁移**（`migrate-export`，导入复用 `bundle-import`）：迁移包
  与 Bundle 容器一体（双层密封），清单扩展为 persona 文件 +
  `bundles/` 快照树——换一台机器落盘后 `setup` 即用。导入侧
  relpath 白名单（集内文件或 `bundles/<名>/<文件>` 安全组件），
  `..`/绝对路径/集外名一律拒；子树父目录自动 0700。

## [0.7.6] — 2026-11-24

### 新增

- **两层访问控制·防越权层**：安装期属主绑定——`init`/`setup` 在
  profile 写入 `.owner`（当前 uid，0600）；新探针
  `access-owner-bound`（uid 不一致即判离）与
  `access-perms-locked`（profile 目录 0700、config/guest-profile/
  sources 必须 0600，任何放宽判离）。state 树各级目录收紧
  0700（纵深防御）。
- 探针清单 +2（ROADMAP/README 同步）。

## [0.7.5] — 2026-11-24

### 新增

- **Persona 原子切换**（`persona-save` / `persona-use` /
  `persona-list`）：账号↔专属出口↔身份文件整体快照到
  `<profile>/bundles/<name>/`；切换时先停机校验，再暂存式换回
  （任一环失败不留半切换状态），随后重建 VM 磁盘完成物理隔离——
  同一 VM 串联两个账号身份的坑不存在。persona 名仅允许
  `[A-Za-z0-9_-]`，路径注入天然免疫。

## [0.7.4] — 2026-11-24

### 新增

- **Identity Bundle 双层加密容器**（`bundle-export` / `bundle-import`）：
  内层明文打包 persona（`guest-profile.json` + `config.json` +
  `sources.json`，跨设备一致）；外层主密码 argon2id →
  XChaCha20-Poly1305 密封——"换电脑不换虚拟指纹，没授权打不开包"。
  主密码经 `CREANCE_BUNDLE_PASSWORD` 提供；导入拒绝覆盖既有文件、
  拒绝集外文件名、错误密码一个文件都不落地。

## [0.7.3] — 2026-11-24

### 新增

- **`creance identity-reset` — 指纹一键重置**：轮换 guest 身份指纹
  （hostname/username/session_token，重建实例随之换 machine-id），
  VM 磁盘重建、宿主 workspace 不动。运行中实例拒绝（先 `creance
  stop`）；客机配置不可读时拒绝盲删（F-022 纪律）。

## [0.7.2] — 2026-11-24

### 新增

- **时区跟随实测出口**（`timezone: "auto"`）：配置接受 `"auto"`；
  `gate-open` 观测到出口国别后，把该国的规范时区（42 国
  `CANONICAL_TZ` 表，最大城市时区）写进 guest `~/.creance-tz`
  （best-effort，写不进不否定观测）。OAuth 通道启动浏览器时
  `~/.creance-tz` 优先于 provision 期 `SESSION_TZ`——persona 时区
  自动对齐出口，不再需要手填。指纹判词把 `"auto"` 视为必然一致。
  provision 期 `"auto"` 落 `Etc/UTC` 中性基线，等待首次观测。

## [0.7.1] — 2026-11-24

### 新增

- **`creance oauth` — 按需 OAuth/验证通道**：guest 内预装
  `creance-oauth` 脚本（Xvnc 虚拟显示 + openbox + creance-browser +
  noVNC/websockify，全部绑 127.0.0.1，setsid 脱离 ssh 会话存活）；
  宿主侧 `ssh -L` 空闲端口转发到 noVNC 页面，回车即用即毁
  （X 桌面/浏览器/noVNC/转发全部回收）。OAuth 的 localhost 回调在
  guest 内天然闭环。toolchain 腿补装
  tigervnc-standalone-server/novnc/websockify/openbox。

### Fixed

- 执行测试的 stub 路径重写器：目录前缀只在 token 边界命中——
  `/usr/local/bin/…` 内的 `/bin/` 曾被二次重写成
  `$STUB/usr/local/$STUB/bin/…` 不可达路径。

## [0.7.0] — 2026-11-24

### 新增（0.6.8 规格落进 0.7.x 版本线）

- **浏览器进 guest**：provision toolchain 腿新增 Chrome for Testing
  官方构建（158.0.8127.88，linux64/linux-arm64 双架构 sha256 钉死，
  与 node tarball 同一供应链纪律——不匹配的 zip 拒解包）；运行库
  经 apt 补装，软链 `/usr/local/bin/creance-browser`。实机验证：
  guest 内 `creance-browser --headless` 真实渲染。
- **出口指纹四元组探针**：`exit_policy::fingerprint_verdict`——实测
  出口国别 ↔ VM 时区 ↔ 浏览器语言 ↔ locale 语言一致性表（42 国）。
  "US IP + 东八区 + 中文语言"式穿帮组合现在：
  (a) `gate open` 时 fail-closed（外网保持关闭）；
  (b) escape 探针 `exit-fingerprint-consistent` 判 ESCAPE。
  未登记国别/代理未运行不定罪（NotEnforced）。`Etc/UTC` 视为中立
  时区，`en_US` locale 视为通用基线——默认配置在任意登记出口保持绿。

All notable changes to creance are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[SemVer](https://semver.org/). During 0.x, breaking changes bump the minor.

## [0.6.25] — 2026-11-23

### Fixed — night-28b (R32 self-audit; child-auditor session was
quota-suspended, main session ran the round itself)

Mutation-verified every R31 fix — 14 injected bypass shapes all went
red — and closed five residuals the sweep found:

- **fuse-region escape** — a `let mut warm = true;` declared just
  BEFORE `let mut core_down_ticks` landed outside the pinned region
  and passed everything. The writable-state helpers are now pinned
  prod-wide: `let mut` == 18, `= true;` == 2, `= false;` == 2,
  `mem::take`/`u32::from` absent; the region pins keep `let mut` == 2
  and the `bool` ban inside the fuse body.
- **ExecStartPost never executed** — the stub-root run proved the
  bootstrap writes the unit, but `systemctl` being stubbed meant the
  stamp line (`iptables-save | grep … > /run/egress-armed`) never
  ran. The test now extracts the unit's literal `sh -c '…'` command,
  replays `iptables-save`/`grep` against the written rules.v4 in the
  same stub root, and asserts the stamp contains exactly the OUTPUT
  rules the privileged probe reads back.
- **rewrite-order corruption** — the stub-root path rewrite used
  sequential `.replace()` calls: `/usr/` → `$STUB/usr/` inserted text
  containing `/sbin/` and `/bin/`, which later passes re-rewrote into
  garbage. Rewrites now run as a single left-to-right pass over the
  earliest matching prefix.
- **top-level verb gaps** — `mv`, `ln`, `chmod`, `chown`, `mkfifo`,
  `mktemp`, `unlink`, `rmdir` added to the banned-token set (all
  legit uses live inside the exempt inner `sh -c` block); `export
  PATH`/`PATH=` line-start prefixes banned (a PATH redirect could
  point `systemctl` at a planted binary).
- Mutation evidence (prod-only, cp-restore harness): `|i, p|` swap,
  dead-closure stop, `mem::zeroed` in vm.rs, fn-pointer verdict
  export, unsafe in an unregistered new file, `Result::Err` guard
  arm, `use … as idir` in lib.rs, bare `false`, `mv`, `export PATH`,
  indented `EGRESSRULES` terminator, `exit 0`, split-quote
  `/bin/systemctl disable`, compound 800ms sleep, pre-decl warm flag
  — every one fails its guard.

## [0.6.24] — 2026-11-23

### Fixed — night-28 (R31 audit round)

Six findings (117–122), all severity S5 — the judge's fourth round of
guard bypasses: every pinned literal was kept verbatim while its
semantics changed underneath it. The fixes move the remaining
counted-shape pins to verbatim line pins, span-aware rules, and
execution-level verification.

- **F-117** — the `verify_and_mark` shell pin covered the callee name
  only: `|i, p|` swapped stop args, a dead `let f = || { stop }`
  closure, a `vm::guest_script_ok`-prefixed canned runner, and a
  substring-checking fake runner all stayed green. The wrapper body
  is now pinned byte-verbatim (`body.trim()` equals the exact
  three-line text) and the two injection tests assert the injected
  script IS `egress_probe_script(vm::nat_allow_hosts())`, not merely
  non-empty.
- **F-118** — the mint-primitive ban covered only 4 of 18 creance-vm
  prod files: `mem::zeroed()` in vm.rs and
  `NonNull::dangling().read()` in qemu/image.rs minted the token, and
  a SAFE `pub(crate) const VERDICT: fn(..) = egress_verdict;` fn
  pointer exported the private verdict. Now the mint bans
  (`transmute`, `MaybeUninit`, `assume_init`, `ptr::read`, `NonNull`,
  `dangling()`, `_sealed` outside gateprobe.rs) and per-file
  `unsafe`/`zeroed` count pins walk EVERY prod file recursively —
  `unsafe` stays `deny` (legit libc calls exist), so counts are
  pinned instead: host.rs 6/2, pidfile.rs 5/0, qemu/mod.rs 4/0,
  runner.rs 3/0, running.rs 2/0, tunnel.rs 2/0, vm.rs 2/0, all others
  0/0. `egress_verdict` occurrences are line-checked (doc comments,
  the gateprobe.rs definition, the `egress_verdict(&out)` call —
  nothing else).
- **F-119** — the Err-arm pin read the first `Err(` line start only:
  a `Result::Err(e) if …` guard arm swallowed the refusal while
  containing a different first `Err(`, and lib.rs could write the
  marker through `use creance_vm::qemu::instance_dir as idir;` plus
  `concat!("provision","ed")`. Now `Result::`/`std::result::Result::`/
  `core::result::Result::` prefixes are stripped before the arm
  check, the arms are pinned as exactly two (`Ok(wrote) => {` and the
  verbatim `Err(e) => return fail(e),`), and six creance-crate prod
  files ban `"provision`/`"isioned"` string fragments, `concat!`,
  `use`-imports and `::instance_dir` path references for
  `instance_dir` (legit uses are all local variables).
- **F-120** — the heredoc-terminator check compared
  `x.trim() == tag`, so ` SKIPRULES` (leading space) terminated the
  span for the test but not for dash, and `exec true`, `true && exit
  0`, or a bare `false` (script's own `set -e`) aborted before the
  lockdown while every count stayed green. The terminator is now
  `*x == tag` byte-exact; top-level command lines are token-scanned
  for banned verbs (`exec`, `exit`, `return`, `eval`, `false`, `cd`,
  `tee`, `dd`, `sudo`, `su`, `kill`, `trap`, `wait`, `source`,
  `cp`, `install`, `xargs`, `builtin`, `chroot`, `setsid`, `nohup`,
  `pushd`, `popd`, `env`/`command`/`nice`/`sudo` line starters,
  absolute-path commands) — heredoc bodies, comments, and the inner
  `timeout … sh -c '…'` toolchain block (a nested `sh` with its own
  quoting where `exit`/`false` are benign) are exempt.
- **F-121** — the whitelist only gated line-STARTING `systemctl` /
  `egress-lock`: `/bin/systemctl disable egress-""lock.service` and a
  `printf … > /etc/system""d/system/net-tune.service` second unit
  passed. Script lines are now normalized (single/double quotes
  stripped) before whitelisting, ANY line containing `systemctl` or
  `egress-lock` must equal a whitelisted literal after
  normalization, and `systemd/system/` writes are count-pinned.
- **F-122** — the watchdog pins counted literals, not lines: a
  renamed `warm` flag (the `grace` word ban respelled) skipped the
  first down tick per stretch, and
  `sleep(Duration::from_millis(500) + Duration::from_millis(300))`
  kept the `from_millis(500)` count while widening the period to
  800ms. The tick and increment lines are now asserted verbatim
  (`std::thread::sleep(Duration::from_millis(500));` ×2,
  `core_down_ticks += 1;` ×1), and the fuse region (counter
  declaration → second reset) may declare no new `let mut` binding
  and contains no `= true;`/`= false;`/`mem::take`/`u32::from`/`bool`.
- **F-120/F-121 execution gate** — `bootstrap_executes_the_lockdown_leg_for_real`
  runs the rendered script under real `sh -e` in a stub root
  (absolute paths rewritten to a temp dir, systemctl/apt/curl/getent
  and friends stubbed) and asserts the artifacts: `rules.v4` bytes
  equal `rules_v4_text`, the unit set is exactly
  `["egress-lock.service"]`, session-env and the sysctl drop-in
  exist, and the systemctl log reads exactly `daemon-reload`,
  `enable egress-lock.service`, `restart egress-lock.service`. An
  early exit of ANY spelling leaves the artifacts unwritten — the
  tests no longer ask whether a line reads right, they ask whether
  the machine state exists.
- Fresh-machine verification on an Ubuntu 24.04 QEMU guest:
  `rm -rf` → `init` → `setup` RC=0 → `up` RC=0 (egress verdict
  proven, marker written, hint printed) → `stop` → `up` RC=0 with
  `restrict=on` in the qemu args.
- Honest residual: token construction carrying no literal (a byte
  array + `from_utf8` spelling `instance_dir` or `"provisioned"`)
  remains detectable only by the compile gate and review, not by
  text scan — noted in the test comment.

## [0.6.23] — 2026-11-23

### Fixed — night-27 (R30 audit round)

Six findings (111–116), all severity S5 — another round of guard
bypasses on the sealed-token chain, the provision script pins, and
the watchdog.

- **F-111** — the production `verify_and_mark` shell had no pins: a
  canned-pass runner or a no-op stop inside it passed every test. The
  wrapper body is now pinned literally (`vm::guest_script` /
  `vm::stop_vm(p, i)`, zero string literals, zero `Ok(`), the
  behavioural fakes assert the injected script is the real probe and
  that stop receives `(profile, instance)` in order, and the body's
  `stop(profile, instance)` arg order plus the verbatim
  `Ok(verified) => Ok(vm::mark_provisioned(…))` arm are pinned.
- **F-112** — the seal was only checked inside gateprobe.rs:
  `pub(super)`/`pub(crate)` verdicts and a `transmute` mint in vm.rs
  stayed green, and the marker could be written before the verdict.
  Now: any `pub`-qualified `fn egress_verdict` line is banned,
  `_sealed`/`transmute` are banned across every creance-vm prod file
  (vm.rs, qemu/mod.rs, qemu/provision.rs, qemu/runner.rs), and the
  verdict→mark positional order is pinned.
- **F-113** — the Err arm pin accepted a comment containing the arm
  text, or a guarded `Err(e) if …` arm placed first; and lib.rs could
  write the marker directly since only main.rs was scanned. Now: the
  first `Err(` line in the call region must be the verbatim
  `Err(e) => return fail(e),`, and every file in the creance crate
  bans a `"provisioned"` literal and any non-`gate_` `instance_dir(`
  call.
- **F-114** — `sh -n` can't prove the cat line executes: an outer
  `: <<'X'` heredoc (dash accepts EOF-terminated) or an early
  `exit 0` swallows it. Now a heredoc span map requires every `<<TAG`
  opener to terminate at a bare TAG line, and the pinned cat/enable
  lines must sit OUTSIDE every span; `exit`/`return` line-starts are
  banned.
- **F-115** — quote-split paths, a `cd`+relative write,
  `systemctl disable` after enable, or an enable line inside a
  heredoc all stayed green. Now all three `cat >` lines, the enable,
  `daemon-reload` and `restart` lines are full-line literal pins that
  must sit outside heredoc spans; `cd`/`pushd`/`popd`/`tee`/`dd`/
  `eval`/`builtin`/`exit`/`return` line-starts are banned; and every
  `systemctl`/`egress-lock` line must be one of the three literals.
- **F-116** — a `grace` counter or an 800ms sampling period widened
  the fuse past the test window. Now `core_down_ticks` bare-count is
  pinned at 5 (decl+inc+threshold+2 resets), `grace` is banned, and
  `from_millis(500)` is pinned at exactly 2 (watchdog tick +
  record-replace loop).

Real-machine re-verify (fresh, per 铁律 4): rm -rf → init → setup
RC=0 → `up` RC=0 (供给完成, marker armed through the sealed chain) →
stop → `up` RC=0 with `restrict=on` present in the qemu args.

## [0.6.22] — 2026-11-23

### Fixed — night-26 (R29 audit round)

Seven findings (104–110), all severity S5 — the sealed-token chain and
its guards still carried bypass channels.

- **F-104** — `verify_and_mark` is now a thin wrapper over
  `verify_and_mark_with(profile, instance, run, stop)`: the guest
  runner and the stop hook are injectable, so a behavioural test
  drives the seam end-to-end — a forged-open output refuses AND stops
  the VM, a runner error refuses AND stops, a pass arms the marker in
  the instance's own `state/qemu/<inst>` directory. Body pins: the
  verdict's input is literally `&out` (bound once), no `.map(`
  between run and verdict, and the body may not contain the
  pass-strings it judges — a canned `"tcp-blocked"` literal is the
  forgery itself.
- **F-105** — the token seal is now compile-enforced both ways:
  `egress_verdict` is private (a `pub` verdict let any workspace crate
  feed it a literal and mint), `mark_provisioned` is `pub(crate)` in
  both vm.rs and qemu/mod.rs, the `_proof: &EgressVerified` signature
  is pinned verbatim (a `&Result`/Option downgrade would arm before
  judging), and the prod region bans `Self { _sealed`, an `impl`
  block, `Default`/`Clone`, `unsafe`/`transmute` — `_sealed: ()`
  exists exactly twice (decl + single mint).
- **F-106** — the Linux marker dispatch could no-op silently (cfg arms
  swapped macos↔linux, `instance_dir` args swapped). Both cfg arms are
  pinned by literal name and the behavioural test asserts the file
  lands at `<profile>/state/qemu/<inst>/provisioned`.
- **F-107** — main.rs's `Err(e)` arm is pinned inside a 600-byte
  window after the call (`return fail(e)` — an `eprintln!`-and-
  continue arm reported "Environment is up" on a dead firewall), and
  the whole creance crate bans a `"provisioned"` literal and
  `instance_dir(&profile` — writing the marker directly there bypasses
  the seal entirely.
- **F-108** — the heredoc exec test sliced only from the `cat >` line,
  so a wrapper opened before it (`if false; then`, an outer
  `: <<'SKIPRULES'`) closed after the slice and never entered it.
  `sh -n` now checks the prefix (wrapped to `exit 0`) and the whole
  rendered script — an unclosed construct fails syntax-check outright.
- **F-109** — substring pins became anchored: the enable line must be
  a whole line (`#`-commented doesn't count), `systemd/` count is
  exactly 1 across all spellings, `cat > ` is exactly 3, `\ncd ` is
  banned, and the egress allowset compares the FULL `grep -vxF` line —
  a trailing appended `-e` can no longer hide.
- **F-110** — watchdog pins hardened: `from_millis(250),` carries its
  trailing comma (a `.max(30s)` chain breaks it), the threshold is the
  verbatim trimmed line `if core_down_ticks >= 3 {` (a `&&`-widened
  condition fails), `let _core_down_ticks` shadow declarations are
  banned (a dead write can't replace a reset), the counter is declared
  exactly once, and the fuse test now asserts the lower bound — still
  Open after ~1.3s, so two dead ticks cannot fuse.

Real-machine re-verify (fresh, per 铁律 4): rm -rf → init → setup
RC=0 → `up` RC=0 (供给完成, marker armed through the sealed chain) →
stop → `up` RC=0 with `restrict=on` present in the qemu args.

## [0.6.21] — 2026-11-23

### Fixed — night-25 (R28 audit round)

- F-099/F-100 (S5): the up-gate verdict chain is now SEALED at the type
  level. New `creance-vm::gateprobe` module mints `EgressVerified` —
  an unforgeable token with a private field — only inside
  `egress_verdict`'s Ok arm; `mark_provisioned` (vm.rs dispatch and
  qemu backend) now takes `&EgressVerified`, so arming the restrict=on
  marker without a real passing verdict is a compile error, not a
  convention a mutation can quietly relax. The whole probe → verdict →
  token → marker chain collapsed into ONE call
  (`gateprobe::verify_and_mark`): main.rs holds no `out` to forge, no
  verdict result to neutralize, no marker call to reorder.
- F-099 (S5): the seven marker-guard bypasses are closed — the source
  walk is recursive and per-file, prod-region slicing pins the
  `#[cfg(test)]` mod to its real shape (a one-line `mod t {}` can no
  longer swallow prod code), inner `#![cfg` attrs and `#[path]` module
  indirection are banned outright, the write path bans `cfg!`/attr
  gates and ANY `.contains(` on the dir (incl. a dual
  `/.creance/`+`/state/qemu/` shape), and the vm.rs dispatch body gets
  the same treatment.
- F-098 (S5): the rules.v4 heredoc is now EXECUTED, not just counted —
  the test slices `cat > … <<'EGRESSRULES' … EGRESSRULES` plus the
  following line into a temp dir and runs it under `sh -e`: a stray
  terminator-shaped line (the v0.6.18 brick, whitespace variants
  included) runs as a command and fails RC=127; `if false` wrapping
  breaks the syntax. Structure pins too: the cat line is literal-equal
  and exactly two lines mention EGRESSRULES.
- F-101 (S5): the fw-fragment allow-set pin now compares the shipped
  `grep -vxF` arg list VERBATIM against the canonical 13-argument set
  built from the renderer's own inputs (entry replacement or embedded
  newlines change the bytes); the systemd unit count uses the broad
  `systemd/system/` path — `cat >/x`, `tee`, drop-ins and second units
  all bump it.
- F-102 (S5): watchdog fuse semantics now have behavioural coverage —
  a dead core during Checking does NOT fuse, fuse latency is asserted
  ≤2.5s, and a fused gate observably kills a real wire process through
  the pidfile path (a spawned `sleep` stands in for the tunnel;
  `reap_orphans` alone won't touch it). Source pins hold the middle:
  250ms sample, >=3 threshold, both counter resets, Open-only
  counting, `tunnel::stop`/`ensure` legs.
- F-103 (S5): OPERATOR-PROMPT 铁律 4 codified — every fix batch's
  real-machine re-verify must include at least one FRESH
  `init → setup → up` leg (the v0.6.18 brick only ever showed on new
  bootstraps).

## [0.6.20] — 2026-11-23

### Fixed — night-24 (R27 audit round)

- F-096 (S4): the v0.6.18 F-094 edit left a stray second `EGRESSRULES`
  line in the rules.v4 heredoc — the rendered bootstrap ran
  `EGRESSRULES` as a command (RC=127), `set -e` aborted before
  egress-lock.service was installed, and every fresh `setup` + `up`
  bricked fail-closed. Removed the stray terminator; the heredoc is
  now checked STRUCTURALLY in tests (exactly one bare terminator line,
  body byte-exact vs `rules_v4_text`).
- F-097 (S5): closed 15 guard-surface bypasses on the F-095
  hardening — the marker-write source scan now walks `src/`
  RECURSIVELY in both crates (new submodule files are in scope),
  allows at most one `#[cfg(test)]` per file, and the "prod region"
  excludes ONLY the trailing test module (code appended after its
  closing brace still counts; prod may never call `tests::*`); the
  up-gate verdict pins the `egress_probe_script` producer call and
  forbids a `let out` shadow; write_marker is also exercised against
  a `~/.creance`-shaped dir and its body may not contain `cfg!`
  compile-gates; the bootstrap pins `ExecStartPost` under ANY
  spelling (systemd accepts blanks around `=`), exactly one unit file
  write, and the probe's allowset is counted exactly (any extra
  entry, e.g. bare tcp, bumps it).
- The QEMU first-boot cloud-init budget is raised 600s → 1200s: on a
  slow link the toolchain download outlasted the old budget and an
  otherwise-healthy first boot was stopped mid-provision (observed on
  this lab: 678s needed). Fail-closed either way — the persistent
  layer lands first — but a slow first `up` no longer fails spuriously.

## [0.6.19] — 2026-11-23

### Added — night-24

- 运行时常驻巡检/自动熔断 (first slice): while the gate is Open the
  lease watchdog now samples the managed core's loopback listener
  every tick (TCP connect, 250 ms timeout). Three consecutive
  failures (≈1.5 s) close the gate with an "auto-fuse" reason and the
  already-closed branch cuts the tunnel on the next tick — end-to-end
  wire cut within ~2 s of core loss, covered by
  `watchdog_fuses_open_gate_when_core_unreachable` (dead port fuses,
  live listener stays open). Sampling is Open-only so the Checking
  window's startup race can't false-fire.

## [0.6.18] — 2026-11-22

### Fixed — night-24 (R26 audit round)

- F-094 (S4): the rules.v4 whole-file allowlist+counts check had two
  remaining lanes — a NUL byte flips GNU grep into binary mode (every
  line filter emits nothing, so an injected `-I OUTPUT -j ACCEPT`
  still read fw-armed) and line counts cannot pin ORDER (`COMMIT`
  early / `*filter` last / `:OUTPUT` after a rule all read armed while
  iptables-restore rejects → next boot unarmed). The persisted file is
  now compared BYTE-EXACT (`cmp -s`) against
  `provision::rules_v4_text` — the new single renderer shared by the
  bootstrap heredoc and the probe, so no second copy can drift. The
  live stamp keeps the `-A OUTPUT` whole-line allowlist. Truth table
  adds NUL + 3 reorder cases; verified on a live restrict=on guest.
- F-095 (S5): the v0.6.17 guard hardening's 11 unguarded mutation
  shapes closed — the marker guard now counts the bare
  `mark_provisioned` name across the WHOLE cli crate (a relay through
  another module counts) and each file is cut at the last line-start
  `#[cfg(test)]` (an injected `// #[cfg(test)]` comment or early
  test-attribute cannot truncate the scan); the verdict must be
  consumed by a literal `match escape::egress_verdict(&out) {`
  (`.or_else(|_| Ok(()))` neutralisation changes the bytes);
  creance-vm counts switch to bare names too (use-as/renamed/
  parenthesized `write_marker` and `mark_provisioned` all count);
  `write_marker` is exercised under a product-shaped instance_dir
  (`…/state/qemu/<inst>`) so a path-prefix gate that declines to
  write fails; the script asserts exactly one `ExecStartPost=` and
  exactly one `egress-armed` occurrence under ANY spelling
  (`/run/./egress-armed`, double-slash paths); a bare
  `-A OUTPUT -j ACCEPT` is asserted absent from the live-side
  allowset.

## [0.6.17] — 2026-11-22

### Fixed — night-23 (R25 audit round)

- F-092 (S4): the rules.v4 side of fw-armed is a WHOLE-FILE check now,
  not a `^-A OUTPUT` line filter — iptables-restore accepts `-I`/`-R`/
  `--append`, leading whitespace, a re-declared `:OUTPUT ACCEPT`, and a
  second `*filter` block, none of which start with `-A OUTPUT`. Every
  non-blank line must literally equal a canonical OUTPUT rule or one of
  the five structural lines, each of which may occur exactly once
  (`*filter`, `:INPUT`/`:FORWARD`/`:OUTPUT DROP [0:0]`, `COMMIT`). The
  live stamp keeps the `-A OUTPUT` filter (iptables-save output is
  already normalized).
- F-093 (S5): the v0.6.16 guard hardening's 9 unguarded mutation
  shapes closed — the marker guard counts the bare `mark_provisioned`
  name in the pre-test region (a `use … as` rename or a parenthesized
  call still counts) and pins the call strictly inside the Ok(()) arm's
  own body, arm-order independent; the creance-vm guard counts
  `write_marker(` too (a direct call skips the whole call-site guard)
  and pins the vm.rs call inside the `pub fn mark_provisioned` body;
  `write_marker` is exercised under a third dir outside the temp dir
  (a path-prefix gate that declines to write now fails); the stamp
  guard counts every `/run/egress-armed` occurrence in the script
  (any spelling — `>`, `>>`, `>/run`, `| tee`); the post-apply tail is
  asserted byte-exact instead of a `iptables` substring blacklist
  (`nft flush` or any other injected line fails); the `-x` in
  `grep -vxF` is itself counted and a canonical-substring line joins
  the truth table.

## [0.6.16] — 2026-11-22

### Fixed — night-23 (R24 audit round)

- F-090 (S4): the fw-armed allowlist is whole-line exact matching
  (`grep -vxF` against the canonical rule lines this product itself
  writes, in both written and iptables-save form) — never a substring
  pattern again. A `-m comment`-forged token, a `!` negation, a port
  range (`--dport 67:65535`), a mixed `NEW,ESTABLISHED` ctstate, or a
  `-p tcp` rule whose comment carries `-p icmp` all read fw-down now;
  each of them had read fw-armed while actually allowing traffic.
  `fw_probe_fragment` takes `nat_hosts: &[&str]` and emits both line
  forms per host, so the canonical set is rendered by the product's own
  NAT-table expansion.
- F-091 (S5): v0.6.15's own guard gaps closed — the marker call-site
  guard counts the bare name (aliases/Err-arms/second sites fail) and
  pins the call between the verdict's `Ok(())` and the probe `Err(e)`
  arms; the creance-vm guard scans `vm.rs` with per-file expected
  counts (mod.rs def-only, runner/provision zero, vm.rs def+dispatch);
  `write_marker` runs under two different dir names so a path-prefix
  gate would be caught; provision asserts the ExecStartPost stamp is
  the only redirect into `/run/egress-armed` and that nothing after the
  apply leg touches netfilter at all; the node-sha `if` is asserted as
  a full line; NAT host tables are pinned to their exact values;
  the executed fw truth table is sliced from the real
  `egress_probe_script` output (the shipped script, not a
  hand-written copy) and covers the F-090 forgery shapes.

## [0.6.15] — 2026-11-22

### Fixed — night-22 (R23 audit round)

- F-086 (S4): the fw-armed check is an allowlist, not a denylist — every
  `-A OUTPUT` line in BOTH `/run/egress-armed` (live stamp) and
  `/etc/iptables/rules.v4` (persisted source) must be `lo`, an
  ESTABLISHED conntrack catch-all, or an ACCEPT to a sanctioned /32 NAT
  host over udp/67 or icmp. A qualified ACCEPT (`-o e+`, `-p tcp`, a
  comment match), a chain jump, or a rules.v4 drift now reads fw-down.
  NAT hosts are single-sourced in `creance_vm::vm::nat_allow_hosts()`.
  Documented residual: intra-boot drift of live netfilter state by a
  privileged guest actor is unobservable unprivileged — and no
  unprivileged path can modify it either.
- F-087 (S5): the probe allowlist fragment runs under real `sh` in a
  truth-table test (STAMP/RULES env overridable); the provisioned
  marker call moved inside the verdict's Ok arm and is guarded as the
  file's single call site; `write_marker` write-once semantics tested;
  provision assertions hardened to exact lines (ExecStartPost, the
  uncommented restart leg, the sha256 conditional, single nodejs.org
  URL); a guard rejects `mark_provisioned` call sites inside
  creance-vm.
- F-088 (S5): CHANGELOG 0.6.10–0.6.14 rewritten against real tag
  ranges — the misplaced idempotent-up, quality-batch, probe-semantics,
  wire, and supply-chain items now sit in their own versions.
- F-089 (S5): r14/r15 verdict tools render against a WRITABLE flag
  path (an unwritable path had rendered the SKIP world — r15 panicked,
  r14 judged a shape the real gate never runs); both re-verified RC=0
  on the armed shape.

## [0.6.14] — 2026-11-22

### Fixed — night-22 (R22 audit round)

- F-082 (S4): the fw-armed probe ran `iptables -L` as the unprivileged
  guest user — permission denied made every `up` fail closed. The
  egress-lock unit now stamps the live OUTPUT section into root-owned
  `/run/egress-armed` (ExecStartPost); the apply leg `systemctl
  restart`s the unit so apply and stamp share one path.
- F-083 (S4): a DROP policy plus a bare `-A OUTPUT -j ACCEPT` no longer
  reads as armed — the probe rejects the unqualified accept.
- F-084 (S5): probe script and verdict factored into
  `escape::egress_probe_script`/`egress_verdict` with per-branch tests;
  `guest_script` places the oracle flag itself (the `oracle_ready`
  parameter is gone); source-order guard pins the provisioned marker
  after the verdict; workbench TE and duplicate-CL get socket-level
  400 tests; provision/Lima pin assertions hardened.
- F-085 (S5): CHANGELOG backfilled for 0.6.10–0.6.13 (this entry itself
  landed after the tag, in 129782d).

## [0.6.13] — 2026-11-22

### Fixed — night-21 (R21 audit round)

- F-078: `guest_script` places the fs-flag oracle itself — no
  caller-supplied `oracle_ready` to wire wrong; wiring test pins it.
- F-079: the v0.6.12 fix surfaces get behavior guards —
  `strict_content_length` ambiguity matrix tests, gate duplicate
  Content-Length → 400 socket test, node tarball sha256 gate and Lima
  image digest pinned assertions.
- F-080: Lima cloud image URL moved from the rolling `release/` dir to
  the immutable dated `release-20261017/` — the pinned digest can no
  longer be invalidated by an Ubuntu refresh (every setup would have
  failed closed).
- F-081: `up` gate now requires positive first-line evidence
  (`fw-armed`) — slirp restrict=on can no longer mask a disarmed guest
  firewall; the `provisioned` marker is written only after every gate
  passes.

## [0.6.12] — 2026-11-22

### Fixed — night-20 (R20 audit round)

- F-076: behavior guards for the v0.6.11 fix surfaces — restrict=on
  lands only with the provisioned marker, QEMU/Lima /32 NAT allow
  tables mutually exclusive, oracle_ready=false single-SKIP, runcmd
  mount-before-bootstrap ordering; r14/r15 verdict tools repaired.
- F-077: restrict=on declaration surfaces aligned; first-provision
  `up` prints the stop+up hint.
- HTTP header parsing consolidated into `creance-net::wire`
  (`parse_header_block` + `strict_content_length`); gate and workbench
  share one parse and reject ambiguous Content-Length.
- Supply chain: node v22.14.0 tarball sha256-pinned per arch (a
  substituted tarball is refused, not unpacked; apt stays the
  fallback); Lima cloudimg digest-pinned. The claude.ai install.sh
  pipe-to-shell remains a documented residual — upstream ships no
  versioned channel.

## [0.6.11] — 2026-11-22

### Fixed — night-19/20 (R19 audit round)

- F-073 (S2): rules.v4 rendered per-backend /32 allows only (QEMU
  10.0.2.2/.3, Lima 192.168.5.2/.3) — a routable path to the host NIC
  is closed.
- F-074: fs-flag probe emits a single SKIP when the oracle cannot be
  placed (no more PASS+SKIP dual verdict).
- F-075: QEMU runcmd mounts before bootstrap; `up` verifies the
  workspace mount (`mountpoint -q`, `mount -a` fallback, honest
  failure).
- slirp `restrict=on`: second line of defense — after provisioning the
  guest's raw-IP egress is cut at NAT level even if in-guest iptables
  is fully bypassed.
- `creance up` is idempotent: an instance already running is reused
  (instance-level flock); a second qemu can no longer clobber qemu.pid
  and orphan the real VM. `DEFAULT_PORT` single-sourced.
- Quality batch: `mihomo -t` and launchctl failures now propagate;
  `sources.json` read errors fail closed instead of minting a fresh
  auth; relay honors `CREANCE_CONFIG`; `proxy-import --url` feeds
  refresh/interval; QMP reads time out (stop/delete can no longer
  block forever on a hung qemu); gate and serve reject ambiguous or
  duplicate Content-Length and Transfer-Encoding smuggling (400);
  PROBE replies need an exact second token; HTTP status lines carry
  reason phrases; gate lock poisoning recovered.
- Probe verdict semantics: a finding emits ESCAPE, a missing tool
  emits SKIP — never a silent PASS.
- Platform shrink: dead code and non-target configuration removed;
  targets are macOS (Apple Silicon) and Ubuntu 24.04 x86_64; the free
  ssh port search no longer collides with its own probe.
- pidfile writes are atomic (write-then-rename).

## [0.6.10] — 2026-11-22

### Fixed — night-18/19 (R18 audit round)

- F-071 (S2): QEMU `up` waited only for sshd, firing the egress probe
  inside the cloud-init provisioning window and killing healthy first
  boots; waits for provisioning to finish.
- F-072 (S2): lockdown lands as persisted artifacts first (rules.v4 +
  egress-lock.service enabled before the toolchain leg); an
  interrupted provision converges to "network up, locked" instead of
  a silently unarmed guest.
- F-068/069/070: probe-oracle and declaration-surface corrections.

## [0.6.9] — 2026-11-22

### Fixed — night-19 (R17 handoff)

- F-067 (S5): README's enforced-probe list still claimed the deleted
  'numeric proxy endpoint' (the space-separated phrase dodged four
  rounds of hyphenated-id sweeps). Removed with an annotation, the
  enumeration completed (external ICMP, positive egress control), and
  README now carries a gate-checked enforced block — all three
  declaration surfaces (ROADMAP, QUICKSTART, README) share the same
  probe-id gate strength.

## [0.6.8] — 2026-11-22

### Fixed — night-18 (R16 handoff)

- F-066 (S5): the probe-id gate's parameterized-family allowlist was a
  free pass — the enforced sock-$s socket-exposure probes are built at
  runtime, invisible to the bidirectional diff, and R16 proved deleting
  them left every automation layer green. The gate now requires the
  family's emission site to be textually present in escape.rs (NC6
  replay fails with a one-line pinpoint). QUICKSTART's category
  enumeration gains the socket class.

## [0.6.7] — 2026-11-22

### Fixed — night-17 (R15 handoff)

- F-065 (S5): the ROADMAP probe inventory missed two live guest probe
  ids — proxy-path (the enforced positive egress control) and
  sock-abstract (the honest-SKIP known gap) — the third recurrence of
  the hand-synced-declaration disease (058 → 063 → 065). The inventory
  is now marker blocks of pure ids, guarded by
  scripts/check-probe-inventory.sh wired into ci.sh: a bidirectional
  diff between code emission sites and the declared inventory — a
  missing id and a ghost id both fail CI with a one-line pinpoint
  (proven by two negative controls). QUICKSTART's category enumeration
  aligned.

## [0.6.6] — 2026-11-21

### Fixed — night-16 (R14 convergence round)

- F-064 (S5): the escape-test missing-line net covered 11 of 12 probes
  — fs-flag-readable emitted through a parameterized shell helper was
  invisible to the expected-id extractor, so that one probe line could
  be swallowed without triggering PROBE transport ESCAPE. The helper is
  gone: the probe emits literally like every other peer and lands in
  the net (r14-convergence [A]/[E] judge green, flipped to post-fix
  assertions).
- (Changelog gap acknowledged: 0.6.2–0.6.5 shipped without entries;
  see git log, docs/AUDIT-2026-11-21.md and harness/findings/.)

## [0.6.1] — 2026-11-21

### Fixed — full-project audit round

Correctness (details in docs/AUDIT-2026-11-21.md):
- the qemu stop ladder's SIGTERM wait judged liveness by the pid file
  that `pidfile::stop` had just deleted — it vacuously succeeded on the
  first tick, the SIGKILL leg was unreachable, and `delete()` could
  unlink the directory of a still-running instance. Waits now probe the
  process (`pidfile::process_alive`).
- `wait_ssh` polled a dead qemu for the full 10-minute budget (hostfwd
  port race kills qemu at spawn) — it now aborts the moment the pid
  file says the process is gone; a failed `up` also stops the half-booted
  VM it leave behind.
- two raw `limactl` queries on macOS bypassed the FINDING-010
  strip-then-set environment discipline (a user-shell LIMA_HOME sent
  them to the global Lima home).
- doctor on aarch64 demanded qemu-system-x86_64; pgrep (the orphan
  sweep's dependency) joined the required-tools checks.
- workspace arguments are validated (absolute, quote-free) BEFORE the
  ~600 MB image download; the image hash is streamed in 8 MiB chunks
  instead of one 600 MB allocation; the gate daemon now gets the relay's
  detach discipline (own process group, stripped environment).

Dead code removed (~500 lines, every claim grep-verified): the whole
`state.rs` ~/.agent-vm legacy, vmname scratch/template machinery, the
never-consumed `SetupOptions.proxy_port`, eleven uncalled paths.rs
helpers plus every fantasy Windows branch (the unix imports at crate
tops made those uncompilable anyway), `Egress::allows`, `credential_env`,
`CAGE_JOB` bookkeeping, three serve.rs leftovers.

Consistency: stale help texts and doc comments thawed to 0.6 reality
(backend split, config resolution order, probe numbering), user-visible
`cage` command names became `creance`, README/ROADMAP/QUICKSTART escape
probe claims updated, harness run-loop now honors the documented
"建议停止" stop verdict, prompts de-personalized.

## [0.6.0] — 2026-11-21

### Added — Linux platform support (Ubuntu, x86_64)

The whole containment stack now runs on Linux hosts, with the macOS
build byte-for-byte untouched in behavior:

- **Native QEMU + cloud-init VM backend** (`creance-vm/src/qemu/`): the
  Ubuntu 24.04 cloud image is downloaded once per profile and verified
  against cloud-images SHA256SUMS; every instance boots a thin qcow2
  overlay with a pure-Rust vFAT `CIDATA` NoCloud seed (fatfs — no
  genisoimage on the host), KVM hard-required (silent TCG refused),
  slirp user networking with exactly one hostfwd (ssh), virtio
  everywhere, the single 9p workspace share, serial-to-log and a QMP
  socket for the stop ladder (powerdown → SIGTERM → token-proven
  SIGKILL). Instance facts live in `instance.json`; the ssh keypair is
  per-instance; cloud-init never grants the guest user sudo at all.
- **In-process managed proxy core**: the same log-relay daemon launchd
  runs, spawned detached in its own process group and pinned by a
  start-token pid file; stop judges liveness by the control socket.
  `physical_interface` on Linux resolves the default-route interface
  from `/proc/net/route` among getifaddrs-reachable non-virtual links.
- **PID-reuse guard armed on Linux**: `process_start_token` reads
  `/proc/<pid>/stat` field 22 (after the last `)` — comm may contain
  delimiters); tunnel/gate/running liveness is start-time-bound again
  instead of silently pid-only.
- **Backend-neutral spine**: `vm::instances_root` / `instance_marker` /
  `SshTarget` / `guest_script` / `instance_running` /
  `declared_mount_count`; tunnel, gate, escape, diagnose and the CLI
  ride them, so the Lima backend keeps working unchanged on macOS.
- `doctor` checks qemu/qemu-img/ssh-keygen and a writable `/dev/kvm` on
  Linux (with install guidance), limactl as before on macOS.

### Fixed

- The pinned node download pointed at a bare `bin/node` path that
  nodejs.org/dist does not ship (404 on every arch — the primary path
  was dead code and slow networks then ate the apt fallback inside the
  300 s budget). It now fetches the official tar.xz and lifts `bin/node`
  out atomically (F-034 discipline kept).
- `install.sh` installed the bundled core into `share/creance/`, a path
  `core_path()` never reads (`../proxy-core/` is its second candidate) —
  installed binaries could not find the core.
- cloud-images SHA256SUMS use GNU binary-mode spelling (`<hash>
  *<file>`); the verifier now strips the asterisk instead of refusing
  every image.
- getifaddrs read the broadcast/peer union on Linux and compared
  `sa_family` as u8 (macOS shapes) — the code had never compiled on
  Linux; `ifa_addr` widened-compare fixes both.

### Verified live (Ubuntu 24.04 host, KVM)

Seven unattended setup→up→shell→escape-test→stop→rebuild cycles: the
vFAT seed is picked up as DataSourceNoCloud, the guest comes up as the
generated identity with no sudo, the 9p workspace is rw, node v22.14.0
lands at /usr/local/bin/node, direct egress/DNS/IPv6 are all dropped,
stop is an ACPI powerdown in seconds with every process reaped, and
escape-test reports 7/7 host probes contained plus every guest probe
PASS except `proxy-path` (the positive control — it needs a real
subscription node). The live network also taught three toolchain
lessons, now guarded by tests: embedded-script quote parity (a lone
apostrophe killed the whole leg in one second), curl-over-urllib on
TLS-fingerprinting networks, and fallback-before-extras ordering under
the 300 s budget.

## [0.5.7] — 2026-11-20

### Fixed — night-13: R11 finding 055

- **F-055**: the provision URL consumed the inner-script ARCH through
  a cross-quote expansion the outer shell never defined — the arch
  segment was empty on every architecture and the pinned node download
  was dead code on the apt fallback. ARCH now expands where it lives;
  the URL's completeness is asserted and probe-verified end to end.

## [0.5.6] — 2026-11-20

### Fixed — night-12: R10 findings 052–054

- **F-052**: night-11's up-refusal edit had been silently overwritten
  (the commit message claimed it; the code never had it) — a deleted
  stamp still skipped the drift check, and `limactl start` on an
  unknown name cloned Lima's default template: an unprovisioned VM
  behind a green exit. The refusal is real now (live-verified both
  cases) and `up` only starts instances this profile set up.
- **F-054**: every provision network step carries a deadline (curl -m,
  apt timeouts) inside one hard 300s toolchain budget — a TCP blackhole
  can no longer get the script killed before the lockdown and sudo
  retirement run. The arch check is POSIX now, so the node download URL
  is finally right on arm64.
- **F-053**: instance names are generated lowercase, matching lima's
  create-time lowercasing — mixed-case names made every existence check
  query a name that never existed.

## [0.5.5] — 2026-11-20

### Fixed — night-11: R9 findings 048–051

- **F-048 (grant path restored)**: the rules reconciliation guessed a
  bare array; the live core answers {"rules":[...]} — every honest core
  was judged divergent and gate-open failed 100% of the time. The
  captured live response is now the frozen fixture of a pure judge
  (with flip/smuggle/bare-array counter-examples).
- **F-049**: a missing or unreadable fingerprint stamp no longer skips
  the drift check — `up` refuses, the escape probe flags a running VM
  without its stamp, and a setup that cannot write the stamp fails.
- **F-050**: an unreadable store (one corrupted sources.json) no longer
  silently blinds both gate-open reconciliations — no store, no
  evidence.
- **F-051**: `creance setup` rebuilds an existing instance (limactl
  delete -f then create; the VM disk is replaced, the host workspace is
  untouched) — every "re-run setup" guidance is finally reachable.

## [0.5.4] — 2026-11-20

### Fixed — night-10: R8 findings 044–047

- **F-044**: `up` no longer refreshes the fingerprint stamp — after the
  promise narrowed to guest-visible fields, a refresh could only
  launder real drift (a bare start never re-provisions). Up now refuses
  to start on drift and points at re-setup.
- **F-045**: the promise fields have a real supply: provision writes
  CAGE_TZ/CAGE_LOCALE/CAGE_LANGUAGE to /etc/profile.d/cage-env.sh (Go
  injects the same trio); browser_language is no longer a vacuous
  promise.
- **F-046**: readiness reconciles the RULES now (a flipped core keeping
  every self-reported field honest while swapping MATCH,CAGE for
  MATCH,DIRECT used to pass), and gate-open reconciles again after the
  trace sample — the flip window shrinks to milliseconds.
- **F-047**: selecting a node is transactional — the old gate's
  revocation comes first and its failure aborts the selection (Go's
  applyProxy semantics), never an open gate behind a changed config
  reported as success.

## [0.5.3] — 2026-11-20

### Fixed — night-09: R7 findings 040–043

- **F-041**: night-08's idempotent sync path stripped exit_policy from
  its comparison, so an anchor change with an unmoved revision kept an
  OPEN gate running on evidence judged against the OLD anchor. The
  anchor is part of "unchanged" now; any drift demands a restart.
- **F-040**: the fingerprint stamp hashed the whole config, so any
  routine host-side operation (a select rotating the revision, an
  anchor tune) left the escape probe permanently red. The stamp now
  records the guest's promise only (timezone, locale, browser
  language); the full fingerprint still guards the up-time running
  lock.
- **F-042**: the core's control socket is enforced by reconciliation,
  not by its secret — live verification showed mihomo's unix controller
  ignores the configured secret entirely (file permissions ARE its
  auth). The secret stays for any TCP path, and gate-open now refuses
  to draw exit evidence from a core whose runtime diverged from its
  generated config (readiness checks mode among everything else).
- **F-043**: selecting a node revokes the gates at once (both CLI and
  workbench paths), matching Go's synchronous applyProxy revocation —
  no more open-gate-with-declared-different-exit window.

## [0.5.2] — 2026-11-20

### Fixed — night-08: R6 findings 036–039

- **F-037 (S2)**: the gate's bearer token lives in memory from start.
  The per-request re-read of the record degraded to an empty token
  when the file was unreadable (chmod 000, the close-removal window)
  and constant_time_eq("", "") passed — a credential-less process
  drove check → grant → open. Live-probe verified: the whole chain now
  403s. A renamed-over loser also no longer accepts the winner's token.
- **F-036**: the exit-drift window is closed. Core restarts (CLI and
  workbench) sync the gate FIRST — a changed exit closes the gate while
  the old core still serves; an idempotent no-change sync keeps the
  gate's state instead of force-retiring it; grants bind to the gate's
  run and the current instant (run_id + created_at minted by gate::open,
  enforced inside the check window, inner/outer report ids symmetric).
  The Go contract's configuration-fingerprint dimension lands with 0.6.
- **F-038**: the evidence's trust boundary is stated honestly — a
  single-destination sample (1.1.1.1-path, now an explicit audit key);
  TLS pins the sample to Cloudflare, single-group core config pins
  evidence to the wire's node, but per-destination routing by the node
  itself is undetectable by one source.
- **F-039**: the ghost workspace manifest at crates/ (a 0.2.0-era
  leftover) is gone; external path-deps resolve the real workspace.
- **R6-H4**: `up` re-pins the fingerprint stamp (proxy_revision is part
  of the fingerprint; a routine proxy-select between runs no longer
  leaves the escape probe permanently red).

## [0.5.1] — 2026-11-19

### Fixed — night-07: R5 findings 032–035

- **F-032**: subscription content can no longer forge the escape verdict.
  A 48-hex password inside imported subscription data (remote,
  attacker-chosen, never reaching the guest) tripped the credentials
  scan into a false escape and exit 1 — a subscription provider could
  weaponize the trust oracle. proxy/sources.json is now explicitly out
  of the probe's scope (whitelisting its fields would be worse: it
  would launder arbitrary hex into the issued set). Live-replayed via
  the poisoning CLI flow: contained, exit 0.
- **F-035**: spawn_daemon no longer dedups on a dying daemon. A live
  pid with no record meant "just starting" or "already exiting";
  deduping there reported up-success with nothing running. The branch
  waits one tick — a fresh daemon publishes its record, a dying one
  exits — then spawns; the run_id handoff absorbs any overlap.
- **F-033**: the fingerprint-consistent probe is alive. Setup pins the
  fingerprint the VM was promised at creation; the probe enforces
  agreement (fresh stamp → contained, drifted config → escape with
  re-pin guidance). Also fixes an intermittent test flake (parallel
  temp-name collisions on subsec-nanos alone).
- **F-034**: the provision node download is atomic (temp + move): a
  mid-transfer curl corpse can no longer sit in /usr/local/bin and
  shadow the apt fallback's working /usr/bin/node.

## [0.5.0] — 2026-11-19

### Added — exit-policy evidence chain (ROADMAP 0.5)

- **`creance gate-open` now grants on evidence, not assertion** (0.4's
  grant carried five self-declared checks, labelled as such): the exit
  is observed live through the configured proxy (Cloudflare trace:
  connecting IP + country), evaluated against the exit-policy anchor —
  static IP equality, dynamic country match, or `any` — under the
  mandatory mainland-IPv4 deny list (6,204 prefixes). Only a Passed
  verdict opens the wire; Failed/Unknown stay closed with the reason and
  the observed exit printed.
- The observation rides the grant as inert evidence keys (`exit_ip`,
  `exit_country`) — part of the record for audit.
- Honesty boundaries, enforced by refusal: region/city-scoped anchors
  evaluate Unknown (the trace source carries no honest region data —
  `colo` is a Cloudflare datacenter, not the exit's region) and stay
  closed until a GeoIP source lands; an unbound default policy refuses
  with binding guidance; a dead proxy means no evidence, never a pass.
- Trust assumption (documented in `evidence.rs`): the observation trusts
  the proxy path to reach 1.1.1.1 — the same trust the wire rests on.
  A second independent trace source for cross-checking is future work.
- `gate::open` takes the caller-supplied checks (the CLI assembles
  structural self-checks + the evidence verdict); the daemon-side
  REQUIRED-set enforcement is unchanged.

### Changed

- Default (unbound) exit policies no longer open: bind a scope in
  config.json first (QUICKSTART has the three recipes). This replaces
  0.4's open-by-default behavior — the gate is now evidence-first.

## [0.4.2] — 2026-11-19

### Fixed — night-06: R4 findings 027–030 + provision fail-open (031)

- **F-028 (S2, live-verified)**: the dual-daemon war. A spawn race or a
  direct `gate-daemon` invocation left a loser alive forever on "a record
  exists", its Closed-state watchdog murdering the winner's tunnel every
  500ms — gate=closed with an intermittently live wire, unmanageable by
  gate-close. The daemon loop now binds to the record's run_id: a
  renamed-over loser retires within a tick, disowned (its drop no longer
  deletes the winner's record — the first fix's live replay caught that
  cascade collapsing the whole gate system), and the watchdog refuses to
  touch the wire it no longer owns. Replay: two daemons converge to one,
  the tunnel pid is stable, the guest wire is continuously up under open
  and continuously down under closed.
- **F-029**: `creance up` mutinied merely slow daemons — any status
  failure (SIGSTOP, a 5s read timeout) deleted the live record, cut the
  tunnel, and spawned a replacement. Liveness evidence is now
  connect-level only (daemon_serving): a frozen daemon still accepts
  connects and is left alone; only ECONNREFUSED/ENOENT retires. retire
  and close_gates share the same errno-based helper (the "unreachable"
  string match is gone). Replay: a frozen daemon makes `up` a pure no-op.
- **F-027**: a dead tunnel ssh lingered as the gate daemon's zombie, and
  zombies pass kill(pid,0) AND keep their start token — ensure()
  short-circuited on the corpse forever (gate Open, wire dead). The
  pid-file liveness check now harvests the caller's own exited children
  via waitpid(WNOHANG); ensure() verifies the ssh survived its settle
  window; reap re-reads ownership before every kill. Replay: kill -9 the
  tunnel, it respawns in ~1s and the guest wire comes back.
- **F-030**: dial targets carrying C0 controls (R4 injected headers into
  an HTTP proxy's CONNECT line via a trailing numeric port) are refused
  at split_addr.
- **F-031**: provision's `set -e` meant a failed apt/mirror aborted the
  script BEFORE the firewall lockdown and sudoers retirement — shipping
  the guest with raw network and passwordless sudo. Installs are
  best-effort now; containment steps always run.
- credentials probe: the store revision (a 48-hex version marker written
  by proxy-select) joined the issued set — the live import+select flow
  tripped the scan as a false escape.

## [0.4.1] — 2026-11-19

### Fixed — night-05: R3 findings 019–023 + three found while fixing (024–026)

- **F-020 (S2, live-verified escape closed)**: the guest user now is the
  generated identity (lima `user:` block: name + neutral comment; uid
  stays host-mirrored — vz virtiofs passes uid numbers through, and that
  mirror is what keeps the writable workspace writable). The cloud-init
  sudoers grant is stripped in provision, the password locked, lima's
  `~/password` file removed: `sudo -n iptables -P OUTPUT ACCEPT` now
  fails — the one-command firewall lift R3 demonstrated is gone. escape
  -test gained `guest-identity` and `guest-privilege` probes. Recreate
  existing environments (`creance stop && creance setup`) to get the new
  guest user.
- **F-019**: a gate record now must prove a serving daemon. spawn_daemon
  pings the record's socket and retires stale records (plus their pid
  file and orphan tunnels) after SIGKILL/reboots; `stop` retires the gate
  via close_and_remove (record removal + immediate tunnel cut); the
  escape gate probe reports "gate record without a live daemon" as an
  ESCAPE instead of blessing the corpse. Live-verified: kill -9 → probe
  flips red → `up` self-heals → probe green, wire still down.
- **F-021**: pid files carry the process start-time token (`pidfile`
  module, shared with running.rs); tunnel/gate stop never signals a
  process the file cannot prove is theirs. A forged pid file against an
  innocent process kills no one.
- **F-022**: username wired end-to-end (ssh tunnel logs in as the
  generated user); load_or_create refuses to reset an unreadable profile
  instead of regenerating identity; the credentials probe scans the whole
  profile directory for token-shaped values against the issued set
  (session token, core auth, gate tokens) — stray secret files are
  escapes; in-guest `env-hex-tokens` probe makes the session token the
  only hex secret in the environment.
- **F-023**: profiles whose physical Lima home cannot fit the socket
  budget fail at setup with an actionable error instead of limactl's raw
  UNIX_PATH_MAX fatal.
- **F-024**: v0.4.0 shipped without its own CI passing (11 fmt diffs, a
  test asserting a removed YAML field) — baseline restored; the release
  gate is a full `scripts/ci.sh` run, always.
- **F-025**: a virgin profile's `up` misread the missing `proxy/`
  directory as daemon failure (spawn succeeded; pid/log writes ENOENT).
  Directories are now created before use; the workbench test no longer
  assumes port 17896 is dead on the host.
- **F-026**: orphan `ssh -R` forwards beyond the pid file's reach are
  reaped by signature (HostKeyAlias + the reverse-forward spec — the
  alias alone also lives in every `limactl shell` client, as the live
  machine demonstrated); "closed = wire down" no longer depends on one
  file's survival.

## [0.4.0] — 2026-11-19

### Added — gate daemon + guest identities (ROADMAP 0.4)
- **gate-daemon**: `creance up` raises a detached gate daemon per
  environment (record-deduped, pid-file managed, stderr logged); `stop`
  retires it via record removal. The gate's watchdog now OWNS the ssh -R
  wire: Closed gate → tunnel down, Open/Checking → tunnel up. Verified
  live: closed = no wire, `gate-open` = wire restored within a second.
- **`creance gate-open` / `gate-close`**: explicit control of the guest's
  only route. The open grant currently carries self-checks only (labelled
  as such); exit-policy evidence integration is 0.5.
- **Guest profiles** (`guest-profile.json`): generated identity —
  cage-<hash> hostname (applied via hostnamectl in provision), non-reserved
  username, 48-hex session token. Created once, never overwritten.
- **One-time credentials**: the ONLY secret the guest receives is the
  cage-issued `CREANCE_SESSION_TOKEN` (provision-time env); rotatable via
  profile rotation. escape-test now hunts host-shaped secrets (API keys /
  private keys) in the guest env — anything beyond the session token is an
  ESCAPE.
- escape-test gate probe enforced: a VM without a gate record is an escape.
- docs/CLOUD-DEVIN.md: Linux-side verification protocol for cloud agents.

## [0.3.0] — 2026-11-19

### Added — the guest network enforcement plane (ROADMAP 0.3)
- Topological containment: provisioned guests get `OUTPUT DROP` by default
  (lo/established/DHCP/ICMP allowed), external DNS and IPv6 disabled —
  direct egress is physically dropped, not merely discouraged. Verified
  live: `net-direct-egress` / `net-dns-external` / `net-ipv6` probes PASS.
- The guest's single wire out: an ssh reverse tunnel (raised by `creance up`,
  torn down by `creance stop`) carrying guest `127.0.0.1:<port>` to the
  host-side core's loopback — the core never leaves host loopback, no LAN
  exposure. Lima's NAT refusing RFC1918 targets and vz rejecting reverse
  portForwards were established experimentally; ssh -R survives both.
- `escape-test` network probes are ENFORCED now (no more SKIP), with a
  positive control (`proxy-path`) proving the only route works; in-guest
  ESCAPE lines fail the run (exit 1).
- `direct`-type nodes importable (explicit DIRECT exit, user-owned choice).

### Fixed
- Instance names budget their length on the PHYSICAL Lima home (deep
  profiles used to blow UNIX_PATH_MAX), restoring isolation after the
  F-010 LIMA_HOME fix exposed real paths.

## [0.2.0] — 2026-11-18

### Added
- Packaged for use: `scripts/install.sh` (build + install + bundled core),
  `docs/QUICKSTART.md`, online-smoke recipe (local mihomo `direct` core —
  real Internet round-trips without owning a node; verified live).
- Night-audit harness (`harness/`): operator prompt with loop/compression/
  findings protocols, 20-entry attack-surface map, escape-drill brief for
  in-VM model red-teaming.
- `escape-test` command: automated containment probes (host-side now,
  in-guest script with a flag-file oracle; unimplemented layers report
  `not enforced` instead of faking a pass).
- `proxy-refresh` (re-fetch URL-backed sources), `proxy-import --url`,
  `serve` workbench (loopback HTTP + single-page UI), `doctor` diagnostics,
  `setup`/`up`/`shell`/`stop` VM lifecycle via limactl, gate control plane
  (unix-socket HTTP state machine with lease watchdog and revision sync).

### Changed
- **Rename to creance**, split into five layered crates: `creance-net`,
  `creance-vm`, `creance-proxy`, `creance-gate`, `creance`. `CREANCE_CONFIG`
  env (legacy `CLAUDE_CAGE_CONFIG` still honored); default profile
  `~/.creance` with legacy `~/.claude-cage` fallback.
- Buffered header reads everywhere (8 KiB chunks + replay reader) replacing
  four byte-at-a-time copies.

### Fixed
- Subscription import: key canonicalization before counting (`Name:`-style
  nodes panicked or collided IDs), ws-headers union merge.
- SSRF: subscription redirects to literal loopback/private/link-local
  targets refused.
- mihomo core spawned with a clean environment (host proxies/credentials no
  longer leak in); relay signal handlers installed before spawn.
- Gate lifecycle: listener/watchdog ownership, socket-directory cleanup,
  poisoned-lock recovery.
- DoH/body reads: Content-Length exact reads (EOF-wait hang), oversize
  probe on length-less bodies, expired deadlines fail fast, dial/TLS honor
  the caller's budget.
- proxy-start idempotence (matching running core is a no-op), launchd
  bootstrap rollback, sha256-based relay/core copies.

## [0.1.0] — 2026-11-18

Initial Rust rewrite of the Claude Cage control plane: proxy-only egress
(SOCKS5/CONNECT/TLS/DoH, zero direct fallback), managed proxy under launchd,
VM lifecycle, exit policy with the mainland deny list, subscription store.
