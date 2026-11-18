//! The state folder (`~/.agent-vm`, or `AGENT_VM_STATE_DIR`): the user's
//! files and agent-vm's per-VM marker files, one file per VM and fact.

use crate::paths;
use std::path::Path;

/// The state folder.
#[derive(Clone, Debug)]
pub struct StateDir(pub String);

/// The markers of a VM.
pub const VERSION_OF: &str = ".agent-vm-version-";
pub const BUILT_BY_OF: &str = ".agent-vm-built-by-";
pub const SSHFS_OF: &str = ".agent-vm-sshfs-";
pub const TERM_OF: &str = ".agent-vm-term-";
pub const FILE_MOUNTS_OF: &str = ".agent-vm-file-mounts-";
pub const MOUNTS_OF: &str = ".agent-vm-mounts-";
pub const CACHE_OF: &str = ".agent-vm-sshfs-cache-";
pub const SCRATCH_OF: &str = ".agent-vm-scratch-";
pub const POLICY_OF: &str = ".agent-vm-policy-";

/// The base template's markers. `BASE_VERSION`, written last by setup, says
/// the base can be cloned.
pub const BASE_VERSION: &str = ".agent-vm-base-version";
pub const BASE_BUILT_BY: &str = ".agent-vm-base-built-by";

const MARKERS: &[&str] = &[
    VERSION_OF,
    BUILT_BY_OF,
    SSHFS_OF,
    TERM_OF,
    FILE_MOUNTS_OF,
    MOUNTS_OF,
    CACHE_OF,
    SCRATCH_OF,
    POLICY_OF,
];

/// `$AGENT_VM_STATE_DIR` (made absolute) or `~/.agent-vm`.
pub fn default_dir() -> Result<StateDir, String> {
    if let Ok(d) = std::env::var("AGENT_VM_STATE_DIR") {
        if !d.is_empty() {
            let abs = if Path::new(&d).is_absolute() {
                d
            } else {
                let wd = std::env::current_dir().map_err(|e| e.to_string())?;
                paths::join(&wd.to_string_lossy(), &d)
            };
            return Ok(StateDir(paths::host(&paths::clean(&abs))));
        }
    }
    let home = paths::home();
    if home.is_empty() {
        return Err("cannot determine the user home".to_owned());
    }
    Ok(StateDir(paths::host(&paths::join(&home, ".agent-vm"))))
}

impl StateDir {
    /// `name` inside the folder, in host spelling.
    pub fn path(&self, name: &str) -> String {
        paths::host(&paths::join(&self.0, name))
    }

    /// The path of marker `kind` for `vm`.
    pub fn marker(&self, kind: &str, vm: &str) -> String {
        self.path(&format!("{kind}{vm}"))
    }

    /// The content of `name` without its trailing newline; `""` when absent.
    pub fn read(&self, name: &str) -> String {
        std::fs::read_to_string(self.path(name))
            .map(|s| s.trim_end_matches('\n').to_owned())
            .unwrap_or_default()
    }

    /// Atomically replaces `name` (temp file renamed over it), creating the
    /// folder when needed. Readers see old or new content, never partial.
    pub fn write(&self, name: &str, data: &[u8]) -> Result<(), String> {
        std::fs::create_dir_all(&self.0).map_err(|e| e.to_string())?;
        let tmp = self.path(&format!(".tmp-{name}-{}", crate::token()[..8].to_owned()));
        std::fs::write(&tmp, data).map_err(|e| e.to_string())?;
        std::fs::rename(&tmp, self.path(name)).map_err(|e| {
            let _ = std::fs::remove_file(&tmp);
            e.to_string()
        })
    }

    /// Read for a marker of `vm`.
    pub fn read_marker(&self, kind: &str, vm: &str) -> String {
        self.read(&format!("{kind}{vm}"))
    }

    /// Moves what is known of VM `from` to `to`: its markers and its staged
    /// single files. Shares are set again before the VM next boots.
    pub fn rename(&self, from: &str, to: &str) -> Result<(), String> {
        let mut last = None;
        for kind in MARKERS {
            if let Err(e) = std::fs::rename(self.marker(kind, from), self.marker(kind, to)) {
                if e.kind() != std::io::ErrorKind::NotFound {
                    last = Some(e.to_string());
                }
            }
        }
        let staged = self.path(&format!("file-mounts/{from}"));
        let staged_to = self.path(&format!("file-mounts/{to}"));
        if let Err(e) = std::fs::rename(&staged, &staged_to) {
            if e.kind() != std::io::ErrorKind::NotFound {
                last = Some(e.to_string());
            }
        }
        last.map_or(Ok(()), Err)
    }

    /// Removes what is known of `vm`, once deleted. Deleting the base
    /// template retires the markers that say it can be cloned.
    pub fn forget(&self, vm: &str, template: &str) -> Result<(), String> {
        let mut last = None;
        for kind in MARKERS {
            if let Err(e) = std::fs::remove_file(self.marker(kind, vm)) {
                if e.kind() != std::io::ErrorKind::NotFound {
                    last = Some(e.to_string());
                }
            }
        }
        let staged = self.path(&format!("file-mounts/{vm}"));
        if let Err(e) = std::fs::remove_dir_all(&staged) {
            if e.kind() != std::io::ErrorKind::NotFound {
                last = Some(e.to_string());
            }
        }
        if vm == template {
            for f in [BASE_VERSION, BASE_BUILT_BY] {
                if let Err(e) = std::fs::remove_file(self.path(f)) {
                    if e.kind() != std::io::ErrorKind::NotFound {
                        last = Some(e.to_string());
                    }
                }
            }
        }
        last.map_or(Ok(()), Err)
    }

    /// The base `vm` was cloned from, for `list`: the builder version and
    /// the day, `"0.1.0 -"` when not known.
    pub fn base_label(&self, vm: &str, template: &str) -> String {
        let (ver_file, by_file) = if vm == template {
            (BASE_VERSION, BASE_BUILT_BY)
        } else {
            (
                &*format!("{VERSION_OF}{vm}"),
                &*format!("{BUILT_BY_OF}{vm}"),
            )
        };
        let mut by = self.read(by_file);
        // An empty value is not a valid build label either.
        if by.is_empty()
            || !by
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'+' | b'-'))
        {
            by = "0.1.0".to_owned();
        }
        let mut day = "-".to_owned();
        let built = self.read(ver_file);
        if !built.is_empty() && built.bytes().all(|c| c.is_ascii_digit()) && built != "0" {
            if let Ok(secs) = built.parse::<u64>() {
                let (y, m, d) = crate::civil_from_days(secs / 86_400);
                day = format!("{y:04}-{m:02}-{d:02}");
            }
        }
        format!("{by} {day}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_state() -> StateDir {
        let dir =
            std::env::temp_dir().join(format!("cage-state-{}", crate::token()[..12].to_owned()));
        std::fs::create_dir_all(&dir).unwrap();
        StateDir(dir.to_string_lossy().into_owned())
    }

    #[test]
    fn write_is_atomic_and_read_strips_newline() {
        let state = temp_state();
        state.write("plain", b"hello\n").unwrap();
        assert_eq!(state.read("plain"), "hello");
        // No temp files linger.
        let entries: Vec<_> = std::fs::read_dir(&state.0).unwrap().collect();
        assert_eq!(entries.len(), 1);
        std::fs::remove_dir_all(&state.0).unwrap();
    }

    #[test]
    fn rename_moves_every_marker() {
        let state = temp_state();
        state
            .write(&format!("{VERSION_OF}old"), b"1700000000\n")
            .unwrap();
        state.write(&format!("{POLICY_OF}old"), b"p\n").unwrap();
        std::fs::create_dir_all(state.path("file-mounts")).unwrap();
        std::fs::write(state.path("file-mounts/old"), b"f").unwrap();
        state.rename("old", "new").unwrap();
        assert_eq!(state.read_marker(VERSION_OF, "new"), "1700000000");
        assert_eq!(state.read_marker(POLICY_OF, "new"), "p");
        assert!(std::fs::read(state.path("file-mounts/new")).is_ok());
        assert_eq!(state.read_marker(VERSION_OF, "old"), "");
        std::fs::remove_dir_all(&state.0).unwrap();
    }

    #[test]
    fn forget_removes_and_retires_the_base() {
        let state = temp_state();
        state.write(&format!("{VERSION_OF}vm"), b"1\n").unwrap();
        state.write(BASE_VERSION, b"2\n").unwrap();
        state.write(BASE_BUILT_BY, b"cage-rs\n").unwrap();
        state.forget("vm", "base").unwrap();
        assert_eq!(state.read_marker(VERSION_OF, "vm"), "");
        // The base template itself is untouched by a non-base forget.
        assert_eq!(state.read(BASE_VERSION), "2");
        state.forget("base", "base").unwrap();
        assert_eq!(state.read(BASE_VERSION), "");
        assert_eq!(state.read(BASE_BUILT_BY), "");
        std::fs::remove_dir_all(&state.0).unwrap();
    }

    #[test]
    fn base_label_formats_the_day() {
        let state = temp_state();
        // 2023-11-01 00:00:00 UTC = 1698796800.
        state.write(BASE_VERSION, b"1698796800\n").unwrap();
        state.write(BASE_BUILT_BY, b"cage-rs-0.1.0\n").unwrap();
        assert_eq!(state.base_label("base", "base"), "cage-rs-0.1.0 2023-11-01");
        // Unknown values fall back to the 0.1.0 label.
        assert_eq!(state.base_label("other", "base"), "0.1.0 -");
        std::fs::remove_dir_all(&state.0).unwrap();
    }

    #[test]
    fn default_dir_honors_the_env_override() {
        // Not set: the home default. Set: honored verbatim (made absolute).
        std::env::remove_var("AGENT_VM_STATE_DIR");
        let d = default_dir().unwrap();
        assert!(d.0.ends_with(".agent-vm"), "{}", d.0);
        std::env::set_var("AGENT_VM_STATE_DIR", "/tmp/cage-state-override");
        assert_eq!(default_dir().unwrap().0, "/tmp/cage-state-override");
        std::env::remove_var("AGENT_VM_STATE_DIR");
    }
}
