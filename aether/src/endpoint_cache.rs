//! Persist last working edge so the next connect can try a warm path first.
use std::net::SocketAddr;
use std::path::PathBuf;

pub fn cache_path(kind: &str) -> PathBuf {
    if let Ok(base) = std::env::var("AETHER_CONFIG") {
        let p = PathBuf::from(base);
        let stem = p
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("aether");
        let parent = p.parent().unwrap_or_else(|| std::path::Path::new("."));
        return parent.join(format!("{stem}-{kind}-lastconn.txt"));
    }
    PathBuf::from(format!("aether-{kind}-lastconn.txt"))
}

pub fn load(kind: &str) -> Option<SocketAddr> {
    let path = cache_path(kind);
    let text = std::fs::read_to_string(&path).ok()?;
    let line = text.lines().next()?.trim();
    if line.is_empty() {
        return None;
    }
    match line.parse::<SocketAddr>() {
        Ok(a) => {
            log::info!("[+] warm endpoint from cache ({kind}): {a}");
            Some(a)
        }
        Err(_) => None,
    }
}

pub fn save(kind: &str, addr: SocketAddr) {
    let path = cache_path(kind);
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Err(e) = std::fs::write(&path, format!("{addr}\n")) {
        log::debug!("endpoint cache write {path:?}: {e}");
    } else {
        log::debug!("[+] saved warm endpoint ({kind}): {addr}");
    }
}
