use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LastConnection {
    pub peer: String,
    #[serde(default)]
    pub profile: String,
}

pub fn load(path: &str) -> Option<LastConnection> {
    let text = std::fs::read_to_string(path).ok()?;
    match toml::from_str(&text) {
        Ok(conn) => Some(conn),
        // A file that exists but does not parse is a different fact from "no
        // cache": it means the next connect pays for a full scan and nothing in the
        // log says why.
        Err(e) => {
            log::warn!("[lastconn] {path} is unreadable ({e}); reconnecting will rescan");
            None
        }
    }
}

pub fn save(path: &str, peer: &str, profile: &str) {
    let conn = LastConnection {
        peer: peer.to_string(),
        profile: profile.to_string(),
    };
    match toml::to_string_pretty(&conn) {
        Ok(text) => {
            // The same locked-down atomic writer the identity file uses: a plain
            // `fs::write` left a truncated file if the process died mid-write, and
            // a truncated file parses as "no cache", so quick reconnect silently
            // paid for a full scan with nothing logged at a level anyone reads.
            if let Err(e) = crate::config::write_private_file(path, text.as_bytes()) {
                log::warn!("[lastconn] failed to save {path}: {e}");
            }
        }
        Err(e) => log::warn!("[lastconn] failed to encode: {e}"),
    }
}

/// Path for the last-connection cache (smart reconnect). Sibling of the
/// engine config so it moves with the user's profile.
pub fn cache_path(base_config: &str) -> String {
    if let Some(p) = crate::runtime_env::var("AETHER_LASTCONN_PATH") {
        return p;
    }
    sibling_of(base_config, "lastconn.toml")
}

/// `<dir>/<name>` beside the config file, through `Path` rather than by hunting
/// for the last `.` in the whole string: with `AETHER_CONFIG` set to a directory
/// (`/var/data/aether/`) the string version split at that trailing separator,
/// found an empty file name, and produced `/var/data/aether/.lastconn.toml`.
fn sibling_of(base_config: &str, extra: &str) -> String {
    let base = std::path::Path::new(base_config);
    let stem = base
        .file_stem()
        .and_then(|s| s.to_str())
        .filter(|s| !s.is_empty())
        .unwrap_or("aether");
    base.parent()
        .unwrap_or_else(|| std::path::Path::new(""))
        .join(format!("{stem}.{extra}"))
        .to_string_lossy()
        .into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The sibling path used to be string surgery on the whole value. Handed a
    /// directory (`AETHER_CONFIG=/var/data/aether/`) it split at the trailing
    /// separator, found an empty file name, and wrote
    /// `/var/data/aether/.lastconn.toml` — a dot-prefixed file nothing reads and
    /// the reconnect log reports as "no cache".
    #[test]
    fn the_lastconn_file_is_a_sibling_of_the_config() {
        crate::runtime_env::remove("AETHER_LASTCONN_PATH");
        for base in [
            "/home/u/.config/aether/aether.toml",
            "C:/Users/o.brien/aether/aether.toml",
            "/var/data/aether/",
            "aether.toml",
        ] {
            let got = cache_path(base);
            let p = std::path::Path::new(&got);
            let name = p.file_name().and_then(|s| s.to_str()).unwrap_or("");
            assert!(name.ends_with(".lastconn.toml"), "{base} -> {got}");
            assert!(
                !name.starts_with('.'),
                "{base} -> {got}: an empty stem means the config name was lost"
            );
            assert_eq!(
                p.parent(),
                std::path::Path::new(base).parent(),
                "{base} -> {got} is not beside the config"
            );
        }
    }
}
