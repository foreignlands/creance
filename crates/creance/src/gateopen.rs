//! Evidence-driven gate-open flow shared by the CLI and the workbench.

use creance_gate::gate;
use creance_vm::config;

/// The evidence-driven gate-open flow, extracted (0.9.2) so the workbench
/// can open the wire through the exact path the CLI uses — before this the
/// serve layer had no way to open the gate at all, leaving workbench users
/// with a running core and a permanently closed wire.
pub fn gate_open_flow(profile: &str, instance: &str) -> Result<String, String> {
    let instance_dir = creance_vm::paths::join(&creance_vm::vm::instances_root(profile), instance);
    // 0.5: a grant needs live exit evidence. Observe the exit through
    // the configured proxy, evaluate it against the anchor (plus the
    // mandatory mainland deny list), and only a Passed verdict opens
    // the wire — anything else stays closed with the reason.
    let cfg = config::load(&config::config_path())?;
    // F-042: the core's unix controller ignores the configured secret
    // (live-verified), so a flipped core (mode=direct, a MATCH,DIRECT
    // reload) would feed the evidence sample whatever the flipper
    // wants. Reconcile the running core against its generated config
    // first — a diverged core may not supply exit evidence.
    // F-050: a store that cannot be read is not a reason to skip the
    // reconciliation — corrupting sources.json used to blind both
    // checks at once. Gate-open is a safety-sensitive path: no store,
    // no evidence.
    match creance_proxy::load(profile) {
        Ok(store) => {
            if let Err(e) = creance_proxy::service::check_running(profile, &store) {
                return Err(format!(
                    "核心运行态已偏离配置（{e}），拒绝采样出口证据，外网保持关闭"
                ));
            }
        }
        Err(e) => return Err(format!("代理配置不可读，拒绝采样出口证据：{e}")),
    }
    let (location, corroborated) = match crate::evidence::observe_full(&cfg) {
        Ok(l) => l,
        Err(e) => return Err(format!("出口观测失败，外网保持关闭：{e}")),
    };
    // F-046: reconcile AGAIN after the sample — a core flipped inside
    // the check→observe window cannot have supplied the evidence. The
    // residual window shrinks to the milliseconds between sample and
    // this check.
    match creance_proxy::load(profile) {
        Ok(store) => {
            if let Err(e) = creance_proxy::service::check_running(profile, &store) {
                return Err(format!(
                    "核心运行态已偏离配置（{e}），拒绝采样出口证据，外网保持关闭"
                ));
            }
        }
        Err(e) => return Err(format!("代理配置不可读，拒绝采样出口证据：{e}")),
    }
    let (state, message) = cfg.exit_policy.evaluate(&location.ip, Some(&location));
    if state != creance_vm::exit_policy::State::Passed {
        return Err(format!(
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
        return Err(format!(
            "出口指纹四元组穿帮，外网保持关闭：{reason}（实测出口 {} {}）",
            location.ip, location.country_code
        ));
    }
    // 时区跟随（0.7.x）：实测出口落地后，把该国的规范时区写进 guest
    // ~/.creance-tz——OAuth 通道启动浏览器时优先采用。best-effort：
    // 写不进去不否定这次观测本身。
    if cfg.timezone == "auto"
        && let Some(zone) = creance_vm::exit_policy::canonical_timezone(&location.country_code)
    {
        let _ = creance_vm::vm::guest_script(
            profile,
            instance,
            &format!("printf '%s\\n' '{zone}' > \"${{HOME:-/tmp}}/.creance-tz"),
        );
    }
    gate::open(
        &instance_dir,
        &crate::evidence::grant_checks_with(&location, corroborated),
    )
    .map(|s| {
        format!(
            "open (epoch {}，出口 {} {})",
            s.epoch, location.ip, location.country_code
        )
    })
}
