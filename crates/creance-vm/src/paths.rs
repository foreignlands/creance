//! Host path helpers: `/`-separated paths, compared case-insensitively
//! where the local filesystem ignores case (macOS), joined lexically the
//! way `cd` resolves `.` and `..`.

/// Whether the local filesystem ignores case by default (macOS).
pub fn no_case() -> bool {
    cfg!(target_os = "macos")
}

/// The user's home folder; `""` when unknown.
pub fn home() -> String {
    std::env::var_os("HOME")
        .map(|h| h.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// Whether `p` is absolute: starts with `/`.
pub fn is_abs(p: &str) -> bool {
    p.starts_with('/')
}

/// Lexical join: `dir/p` with `.` and `..` resolved as `cd` does. `..` stops
/// at the root.
pub fn join(dir: &str, p: &str) -> String {
    let mut out = dir.trim_end_matches('/').to_owned();
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
        "/".to_owned()
    } else {
        out
    }
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
        // An absolute second operand is joined textually.
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
    fn no_case_tracks_the_platform() {
        // macOS folds; Linux does not — asserted per-platform, not by name.
        assert_eq!(no_case(), cfg!(target_os = "macos"));
    }
}
