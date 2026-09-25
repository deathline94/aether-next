use serde::{Deserialize, Serialize};
use crate::cache::TransportKind;

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct LastConnection {
    pub peer: String,
    #[serde(default)]
    pub profile: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LastConnectionFile {
    #[serde(default)]
    pub h2: Option<LastConnection>,
    #[serde(default)]
    pub h3: Option<LastConnection>,
    /// Legacy unlabelled entry (from previous version when there was only top-level `peer = "..."`).
    /// Deserialized so old files parse cleanly, but explicitly ignored because we
    /// MUST treat legacy unlabelled entries as unknown (never infer transport from IP/port).
    #[serde(default)]
    pub peer: Option<String>,
    #[serde(default)]
    pub profile: Option<String>,
}

pub fn load_file(path: &str) -> Option<LastConnectionFile> {
    let text = std::fs::read_to_string(path).ok()?;
    match toml::from_str(&text) {
        Ok(file) => Some(file),
        Err(e) => {
            log::warn!("[lastconn] {path} is unreadable ({e}); reconnecting will rescan");
            None
        }
    }
}

pub fn load_for(path: &str, transport: TransportKind) -> Option<LastConnection> {
    let file = load_file(path)?;
    match transport {
        TransportKind::H2 => file.h2,
        TransportKind::Quic => file.h3,
        _ => None,
    }
}

pub fn load(path: &str) -> Option<LastConnection> {
    load_for(path, crate::cache::active_masque_transport())
}

pub fn save(path: &str, peer: &str, profile: &str, transport: TransportKind) {
    let mut file = load_file(path).unwrap_or_default();
    let conn = LastConnection {
        peer: peer.to_string(),
        profile: profile.to_string(),
    };
    match transport {
        TransportKind::H2 => file.h2 = Some(conn),
        TransportKind::Quic => file.h3 = Some(conn),
        _ => return,
    }
    // Remove legacy unlabelled fields if present
    file.peer = None;
    file.profile = None;

    match toml::to_string_pretty(&file) {
        Ok(text) => {
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

    #[test]
    fn legacy_unlabelled_entries_return_none() {
        let dir = std::env::temp_dir().join(format!("aether_lastconn_legacy_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("lastconn.toml");
        let path_str = path.to_str().unwrap();

        // Legacy unlabelled file: has top-level peer
        let legacy_content = "peer = \"162.159.198.1:443\"\nprofile = \"standard\"\n";
        std::fs::write(&path, legacy_content).unwrap();

        // Both H2 and H3 should treat legacy unlabelled entries as unknown
        assert!(load_for(path_str, TransportKind::Quic).is_none(), "legacy unlabelled must be unknown for H3");
        assert!(load_for(path_str, TransportKind::H2).is_none(), "legacy unlabelled must be unknown for H2");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn h2_and_h3_records_are_isolated_and_preserved() {
        let dir = std::env::temp_dir().join(format!("aether_lastconn_iso_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("lastconn.toml");
        let path_str = path.to_str().unwrap();

        // Save H2 record
        save(path_str, "162.159.193.1:443", "h2-profile", TransportKind::H2);
        let h2_loaded = load_for(path_str, TransportKind::H2).expect("h2 record");
        assert_eq!(h2_loaded.peer, "162.159.193.1:443");
        assert_eq!(h2_loaded.profile, "h2-profile");
        assert!(load_for(path_str, TransportKind::Quic).is_none());

        // Save H3 record
        save(path_str, "162.159.198.1:443", "h3-profile", TransportKind::Quic);
        let h3_loaded = load_for(path_str, TransportKind::Quic).expect("h3 record");
        assert_eq!(h3_loaded.peer, "162.159.198.1:443");
        assert_eq!(h3_loaded.profile, "h3-profile");

        // Verify H2 record is still intact
        let h2_again = load_for(path_str, TransportKind::H2).expect("h2 record still there");
        assert_eq!(h2_again.peer, "162.159.193.1:443");

        // Update H2 record; H3 must remain intact
        save(path_str, "162.159.193.2:443", "h2-updated", TransportKind::H2);
        assert_eq!(load_for(path_str, TransportKind::H2).unwrap().peer, "162.159.193.2:443");
        assert_eq!(load_for(path_str, TransportKind::Quic).unwrap().peer, "162.159.198.1:443");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
