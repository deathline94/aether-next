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
    let dir_end = base_config.rfind(['/', '\\']).map(|i| i + 1).unwrap_or(0);
    let (dir, file) = base_config.split_at(dir_end);
    let stem = file.rsplit_once('.').map(|(s, _)| s).unwrap_or(file);
    format!("{dir}{stem}.lastconn.toml")
}

/// Path for the QUIC session ticket cache (0-RTT resumption).
pub fn session_ticket_path() -> String {
    let base = crate::runtime_env::var("AETHER_CONFIG").unwrap_or_else(|| "aether.toml".into());
    let dir_end = base.rfind(['/', '\\']).map(|i| i + 1).unwrap_or(0);
    let (dir, file) = base.split_at(dir_end);
    let stem = file.rsplit_once('.').map(|(s, _)| s).unwrap_or(file);
    format!("{dir}{stem}.session")
}

/// Save a QUIC session ticket for 0-RTT resumption on next connect.
/// A session ticket is a resumption credential, so it goes through the same
/// locked-down atomic writer as the identity file (was: plain fs::write with
/// default ACLs/perms).
pub fn save_session_ticket(data: &[u8]) {
    let path = session_ticket_path();
    match crate::config::write_private_file(&path, data) {
        Ok(()) => log::debug!("[lastconn] cached session ticket ({} bytes)", data.len()),
        Err(e) => log::debug!("[lastconn] failed to cache session ticket: {e}"),
    }
}
