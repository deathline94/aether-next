use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LastConnection {
    pub peer: String,
    #[serde(default)]
    pub profile: String,
}

pub fn load(path: &str) -> Option<LastConnection> {
    let text = std::fs::read_to_string(path).ok()?;
    toml::from_str(&text).ok()
}

pub fn save(path: &str, peer: &str, profile: &str) {
    let conn = LastConnection {
        peer: peer.to_string(),
        profile: profile.to_string(),
    };
    match toml::to_string_pretty(&conn) {
        Ok(text) => {
            if let Err(e) = std::fs::write(path, text) {
                log::debug!("[lastconn] failed to save {path}: {e}");
            }
        }
        Err(e) => log::debug!("[lastconn] failed to encode: {e}"),
    }
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
pub fn save_session_ticket(data: &[u8]) {
    let path = session_ticket_path();
    if let Err(e) = std::fs::write(&path, data) {
        log::debug!("[lastconn] failed to cache session ticket: {e}");
    } else {
        log::debug!("[lastconn] cached session ticket ({} bytes)", data.len());
    }
}
