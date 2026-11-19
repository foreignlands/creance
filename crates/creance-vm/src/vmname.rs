//! Instance naming: the VM of a project directory is `<base>-<hash>`, where
//! `base` is the folder name with every run of non-alphanumerics collapsed to
//! one `-`, and `hash` the first 8 hex digits of the path's SHA-256.
//!
//! Names are cut to fit the longest UNIX socket path Lima uses in a given
//! home, so every Cage environment keeps a reachable socket.

use crate::paths;
use sha2::{Digest, Sha256};
use std::path::Path;

/// The base template every project VM is cloned from.
pub const TEMPLATE: &str = "base";

/// The instance-name length a Lima home supports, derived from its socket
/// budget. `0` selects Lima's normal 76-byte cap.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limit(pub usize);

/// `UNIX_PATH_MAX` as Lima spells it per platform.
fn unix_path_max() -> usize {
    if cfg!(target_os = "macos") {
        104
    } else {
        108
    }
}

/// The longest socket filename Lima creates: `ssh.sock` + a 16-char suffix.
const LONGEST_SOCK: &str = "ssh.sock.1234567890123456";

/// Fits the longest socket in this home: `<home>/<name>/<socket>` must stay
/// under `UNIX_PATH_MAX`.
///
/// Lima's formula: <home>/<name>/<socket> must fit UNIX_PATH_MAX-1, i.e.
/// name <= UnixPathMax - 1 - len(home) - len("/") - len("/" + sock).
pub fn home_limit(home: &str, logical: bool) -> Limit {
    Limit((socket_budget(home, logical).clamp(1, 76)) as usize)
}

/// The raw instance-name budget a home leaves, in bytes — it goes negative
/// when the (physical, canonicalized) home is too deep to host a Lima
/// instance at all (F-023). Callers must fail on budgets below the
/// shortest meaningful name (10: `p` + `-xxxxxxxx`), which the clamped
/// `home_limit` cannot express.
pub fn socket_budget(home: &str, logical: bool) -> isize {
    let real = if logical {
        home.to_owned()
    } else {
        resolve_existing(home).unwrap_or_else(|| home.to_owned())
    };
    unix_path_max() as isize - (1 + real.len() + 1 + 1 + LONGEST_SOCK.len()) as isize
}

fn resolve_existing(home: &str) -> Option<String> {
    Path::new(home)
        .canonicalize()
        .ok()
        .map(|c| c.to_string_lossy().into_owned())
}

impl Limit {
    /// The VM name of the project directory `dir`.
    pub fn name(&self, dir: &str) -> String {
        let dir = paths::guest(dir);
        let sum: [u8; 32] = Sha256::digest(dir.as_bytes()).into();
        let base = base_name(&dir, 0).unwrap_or_else(|| "project".to_owned());
        self.fit(&base, &format!("-{}", hex::encode(&sum[..4])))
    }

    /// `b + suffix`, `b` cut to stay within the limit, never to nothing.
    pub fn fit(&self, b: &str, suffix: &str) -> String {
        let max = if self.0 == 0 { 76 } else { self.0 };
        let n = max.saturating_sub(suffix.len());
        let mut base = b.to_owned();
        if base.len() > n {
            // Cut at a UTF-8 boundary within `n` bytes, then trim trailing `-`.
            let mut cut = n.max(1);
            while cut > 1 && !base.is_char_boundary(cut) {
                cut -= 1;
            }
            base.truncate(cut);
            base = base.trim_end_matches('-').to_owned();
            if base.is_empty() {
                base = "p".to_owned();
            }
        }
        base + suffix
    }

    /// A fresh `--scratch` name for `dir`, never the folder's own VM.
    pub fn scratch(&self, dir: &str) -> String {
        let mut b = [0u8; 4];
        rand::fill(&mut b);
        let name = base_name(dir, 20).unwrap_or_else(|| "project".to_owned());
        self.fit(&name, &format!("-scratch-{}", hex::encode(b)))
    }
}

/// Whether `name` looks like a scratch name. Note: a folder literally named
/// `x-scratch` yields `x-scratch-<hash>`, which matches too.
pub fn is_scratch(name: &str) -> bool {
    let Some((head, tail)) = name.rsplit_once("-scratch-") else {
        return false;
    };
    !head.is_empty()
        && head.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-')
        && tail.len() == 8
        && tail
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

/// The last element of `dir`, every run of bytes other than ASCII letters and
/// digits made one `-`, cut to `max` bytes when `max > 0`, without `-` at
/// either end. `None` when nothing is left.
fn base_name(dir: &str, max: usize) -> Option<String> {
    let bytes = basename_bytes(dir);
    let mut out = Vec::new();
    for &c in bytes.iter().chain(std::iter::once(&b'\n')) {
        if c.is_ascii_alphanumeric() {
            out.push(c);
        } else if out.last() != Some(&b'-') {
            out.push(b'-');
        }
    }
    if max > 0 && out.len() > max {
        out.truncate(max);
    }
    let s = String::from_utf8_lossy(&out).into_owned();
    let s = if max > 0 {
        s.trim_matches('-').to_owned()
    } else {
        s.trim_start_matches('-').trim_end_matches('-').to_owned()
    };
    (!s.is_empty()).then_some(s)
}

fn basename_bytes(p: &str) -> &[u8] {
    let t = p.trim_end_matches('/');
    match t.rfind('/') {
        Some(i) => &t.as_bytes()[i + 1..],
        None if t.is_empty() => &[],
        None => t.as_bytes(),
    }
}

/// `dir` (the current directory when empty) as commands that start a VM spell
/// theirs: absolute, cleaned, existing, without control characters.
pub fn abs_dir(dir: &str) -> Result<String, String> {
    let dir = if dir.is_empty() || !Path::new(dir).is_absolute() {
        let wd = std::env::current_dir().map_err(|e| e.to_string())?;
        paths::join(&wd.to_string_lossy(), dir)
    } else {
        dir.to_owned()
    };
    let dir = paths::clean(&dir);
    match Path::new(&dir).metadata() {
        Ok(st) if st.is_dir() => {}
        _ => return Err(format!("no such directory: {dir}")),
    }
    if dir.chars().any(|c| c < ' ' || c == '\x7f') {
        return Err("the directory name contains a control character".to_owned());
    }
    Ok(paths::host(&dir))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_hashes_and_squashes() {
        // sha256("/tmp/")[..4] = ac 35 1c 71 (verified against shasum).
        let n = Limit(0).name("/tmp/");
        assert_eq!(n, format!("tmp-{}", hex::encode([0xac, 0x35, 0x1c, 0x71])));
        // Whitespace and punctuation collapse to one dash; alphanumerics stay.
        let n2 = Limit(0).name("/tmp/My Project (v2)");
        let (base, suffix) = n2.split_at(n2.len() - 8);
        assert_eq!(base, "My-Project-v2-");
        assert!(suffix.bytes().all(|c| c.is_ascii_hexdigit()));
        // The literal path string is hashed: "/tmp" and "/tmp/" differ.
        assert_ne!(Limit(0).name("/tmp"), Limit(0).name("/tmp/"));
    }

    #[test]
    fn fit_never_empties_the_base() {
        // Suffix "-12345678" is 9 bytes; a 12-byte limit leaves 3.
        assert_eq!(Limit(12).fit("abcdefghij", "-12345678"), "abc-12345678");
        assert_eq!(Limit(9).fit("--ab", "-12345678"), "p-12345678");
        assert_eq!(Limit(0).fit("a", "-12345678"), "a-12345678");
        assert_eq!(Limit(10).fit("abcdefghij", "-12345678"), "a-12345678");
    }

    #[test]
    fn base_name_trims() {
        assert_eq!(
            base_name("/tmp/My-Project/", 0).as_deref(),
            Some("My-Project")
        );
        assert_eq!(base_name("/tmp/…", 0), None);
        assert_eq!(base_name("/tmp/…", 3), None);
        assert_eq!(base_name("/tmp/abc", 2).as_deref(), Some("ab"));
    }

    #[test]
    fn home_limit_fits_socket_budget() {
        // Lima's exact formula: UnixPathMax - 1 - home - '/' - '/' + sock.
        let expected = |home: usize| 104usize.saturating_sub(1 + home + 1 + 1 + LONGEST_SOCK.len());
        assert_eq!(home_limit("/tmp/lima", false).0, expected(9));
        let deep = format!("/{}", "d".repeat(60));
        assert_eq!(home_limit(&deep, false).0, expected(deep.len()));
        // The 76-byte default cap only applies when the budget is larger.
        assert_eq!(Limit(0).fit("a", "-12345678").len(), 10);
        // Never below 1.
        assert_eq!(home_limit(&format!("/{}", "d".repeat(500)), false).0, 1);
        // Every derived name keeps the full socket path within budget.
        let home = home_limit(&deep, false);
        let name = home.name("/workspace/project");
        let socket_len = deep.len() + 1 + name.len() + 1 + LONGEST_SOCK.len();
        assert!(socket_len < 104, "socket path {socket_len} must fit");
    }

    #[test]
    fn scratch_matches_only_its_shape() {
        let n = Limit(0).scratch("/tmp/proj");
        assert!(n.starts_with("proj-scratch-"));
        assert!(is_scratch(&n));
        assert!(!is_scratch("base"));
    }
}
