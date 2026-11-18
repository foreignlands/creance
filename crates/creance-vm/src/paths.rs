//! Host path helpers.
//!
//! Paths are spelled with `/` separators everywhere (on Windows as `C:/x`),
//! compared case-insensitively where the local filesystem ignores case, and
//! joined lexically the way `cd` resolves `.` and `..`.

use std::path::{Path, PathBuf};

/// Whether host paths are Windows ones with a drive.
pub fn is_windows() -> bool {
    cfg!(windows)
}

/// Whether the local filesystem ignores case by default (macOS, Windows).
pub fn no_case() -> bool {
    cfg!(target_os = "macos") || is_windows()
}

/// `p` in the host spelling: `/` separators.
pub fn host(p: &str) -> String {
    if is_windows() {
        p.replace('\\', "/")
    } else {
        p.to_owned()
    }
}

/// The user's home folder in host spelling; `""` when unknown.
pub fn home() -> String {
    let var = if is_windows() { "USERPROFILE" } else { "HOME" };
    std::env::var_os(var)
        .map(|h| host(&h.to_string_lossy()))
        .unwrap_or_default()
}

/// `p` with symlinks resolved; the input unchanged when resolution fails.
pub fn real(p: &str) -> String {
    Path::new(p)
        .canonicalize()
        .map(|c| host(&c.to_string_lossy()))
        .unwrap_or_else(|_| p.to_owned())
}

/// The length of `p`'s drive (`"C:"`); 0 when it has none or this is not Windows.
fn volume(p: &str) -> usize {
    if is_windows() {
        let bytes = p.as_bytes();
        if bytes.len() >= 2 && bytes[1] == b':' && bytes[0].is_ascii_alphabetic() {
            return 2;
        }
    }
    0
}

/// Whether `p` is absolute: starts with `/`, after its drive on Windows.
pub fn is_abs(p: &str) -> bool {
    p[volume(p)..].starts_with('/')
}

/// `p`'s root: `/`, or its drive's (`C:/`) on Windows.
fn root(p: &str) -> String {
    p[..volume(p)].to_owned() + "/"
}

/// Lexical join: `dir/p` with `.` and `..` resolved as `cd` does. `..` stops
/// at the root.
pub fn join(dir: &str, p: &str) -> String {
    let v = volume(dir);
    let (drive, mut out) = (
        dir[..v].to_owned(),
        dir[v..].trim_end_matches('/').to_owned(),
    );
    for comp in p.split('/') {
        match comp {
            "" | "." => {}
            ".." => match out.rfind('/') {
                Some(i) => out.truncate(i),
                None => out.clear(),
            },
            other => {
                out.push('/');
                out.push_str(other);
            }
        }
    }
    if out.is_empty() {
        drive + "/"
    } else {
        drive + &out
    }
}

/// `p` made absolute against `dir`.
pub fn abs(dir: &str, p: &str) -> String {
    if is_abs(p) {
        let r = root(p);
        return join(&r, &p[r.len()..]);
    }
    join(dir, p)
}

/// The host path `p` as the VM sees it: on Windows Git Bash spelled `C:\x` as
/// `/c/x`. Elsewhere unchanged.
pub fn guest(p: &str) -> String {
    if volume(p) == 0 {
        return p.to_owned();
    }
    let mut s = String::with_capacity(p.len());
    s.push('/');
    s.push_str(&p[..1].to_lowercase());
    s.push_str(&p[2..].replace('\\', "/"));
    s
}

/// `s` as the filesystem compares it: folded where case is ignored.
pub fn fold(s: &str) -> String {
    if no_case() {
        s.to_lowercase()
    } else {
        s.to_owned()
    }
}

/// Whether two paths name the same location as the filesystem sees it.
pub fn equal(a: &str, b: &str) -> bool {
    if no_case() {
        a.eq_ignore_ascii_case(b)
    } else {
        a == b
    }
}

/// `s` without `prefix` (compared as the filesystem does) and whether it
/// started with it.
pub fn cut_prefix<'a>(s: &'a str, prefix: &str) -> (&'a str, bool) {
    if !no_case() {
        return match s.strip_prefix(prefix) {
            Some(rest) => (rest, true),
            None => (s, false),
        };
    }
    if fold(s).starts_with(&fold(prefix)) && prefix.len() <= s.len() {
        (&s[prefix.len()..], true)
    } else {
        (s, false)
    }
}

/// `p` relative to `dir` (`"."` for `dir` itself); `None` when outside.
pub fn in_dir(p: &str, dir: &str) -> Option<String> {
    let p = p.trim_end_matches('/');
    let dir = dir.trim_end_matches('/');
    if equal(p, dir) {
        return Some(".".to_owned());
    }
    if dir.is_empty() {
        return None;
    }
    let mut prefix = dir.to_owned();
    prefix.push('/');
    cut_prefix(p, &prefix)
        .1
        .then(|| p[prefix.len()..].to_owned())
}

/// Go's `filepath.Clean`: lexical normalization keeping the root.
pub fn clean(p: &str) -> String {
    if p.is_empty() {
        return ".".to_owned();
    }
    let rooted = p.starts_with('/');
    let mut out: Vec<&str> = Vec::new();
    for comp in p.split('/') {
        match comp {
            "" | "." => {}
            ".." => match out.last() {
                Some(&"..") if !rooted => out.push(".."),
                Some(_) => {
                    out.pop();
                }
                None if !rooted => out.push(".."),
                None => {}
            },
            other => out.push(other),
        }
    }
    let mut s = out.join("/");
    if rooted {
        s = format!("/{s}");
    }
    if s.is_empty() {
        s.push('.');
    }
    s
}

/// The last element of `p`, trailing slashes ignored, `/` for the root,
/// `""` for the empty path.
pub fn basename(p: &str) -> String {
    if p.is_empty() {
        return String::new();
    }
    let t = p.trim_end_matches('/');
    if t.is_empty() {
        return "/".to_owned();
    }
    t[t.rfind('/').map(|i| i + 1).unwrap_or(0)..].to_owned()
}

/// `path` as an owned [`PathBuf`].
pub fn to_buf(p: &str) -> PathBuf {
    PathBuf::from(p)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn join_resolves_dots() {
        assert_eq!(join("/a/b", "c"), "/a/b/c");
        assert_eq!(join("/a/b", "../c"), "/a/c");
        assert_eq!(join("/a/b", "../../c"), "/c");
        assert_eq!(join("/a/b", ".."), "/a");
        assert_eq!(join("/a/b", "../../.."), "/");
        assert_eq!(join("/a/b", "."), "/a/b");
        // An absolute second operand is joined textually; paths::abs roots it.
        assert_eq!(join("/a", "/b/c"), "/a/b/c");
    }

    #[test]
    fn clean_matches_filepath_clean() {
        assert_eq!(clean(""), ".");
        assert_eq!(clean("a//b/../c"), "a/c");
        assert_eq!(clean("/.."), "/");
        assert_eq!(clean("../a"), "../a");
        assert_eq!(clean("a/.."), ".");
        assert_eq!(clean("/"), "/");
        assert_eq!(clean("./a/b/"), "a/b");
    }

    #[test]
    fn basename_ignores_trailing_slashes() {
        assert_eq!(basename("/tmp/proj/"), "proj");
        assert_eq!(basename("/"), "/");
        assert_eq!(basename(""), "");
    }

    #[test]
    fn in_dir_reports_containment() {
        assert_eq!(in_dir("/a/b/c", "/a/b").as_deref(), Some("c"));
        assert_eq!(in_dir("/a/b", "/a/b").as_deref(), Some("."));
        assert_eq!(in_dir("/a/bd/c", "/a/b"), None);
        assert_eq!(in_dir("/a", "/a/b"), None);
    }
}
