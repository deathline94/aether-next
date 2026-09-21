import re

p = 'src/config.rs'
s = open(p, encoding='utf-8').read()

# Imports: only what is used now.
s = s.replace(
    'use chacha20poly1305::aead::{Aead, KeyInit};',
    'use chacha20poly1305::aead::KeyInit;',
)

old_load = s[s.index('pub fn load(path: &str) -> Result<Option<Identity>> {'):s.index('pub fn save(path: &str, identity: &Identity) -> Result<()> {')]
new_load = '''pub fn load(path: &str) -> Result<Option<Identity>> {
    quarantine_backup(path);
    if !Path::new(path).exists() {
        return Ok(None);
    }
    let identity = read_identity(path)?;

    // A config that is not in the current envelope is rewritten immediately and
    // then read back through the same code path, so "migrated" is something the
    // process proved rather than something it hoped for.
    let raw = std::fs::read(path)?;
    if !raw.starts_with(MAGIC_V2) {
        if key()?.is_none() {
            return Err(AetherError::Other(
                "config is stored unencrypted and no key is available to seal it: refusing to keep \\
                 identity material in plaintext. Launch through the Aether app or set \\
                 AETHER_CONFIG_KEY."
                    .into(),
            ));
        }
        save(path, &identity)?;
        let after = read_identity(path)?;
        if after.device_id != identity.device_id || after.ipv4 != identity.ipv4 {
            return Err(AetherError::Other(
                "config migration read back a different identity".into(),
            ));
        }
        log::info!("[config] migrated {path} into the v2 envelope");
    }

    Ok(Some(identity))
}

/// Read, authenticate and validate the identity at `path`.
fn read_identity(path: &str) -> Result<Identity> {
    let meta = std::fs::metadata(path)?;
    if meta.len() > MAX_CONFIG_BYTES {
        return Err(AetherError::Other(format!(
            "config too large ({} bytes)",
            meta.len()
        )));
    }
    let raw = std::fs::read(path)?;
    let encrypted = raw.starts_with(MAGIC_V2) || raw.starts_with(MAGIC_V1);
    let plain = match key()? {
        Some(k) => match open(path, &raw, &k)? {
            Some(bytes) => bytes,
            None => raw,
        },
        None if encrypted => {
            return Err(AetherError::Other(
                "config is encrypted but no key is available for this process".into(),
            ))
        }
        None => raw,
    };
    let text =
        String::from_utf8(plain).map_err(|_| AetherError::Other("invalid config encoding".into()))?;
    let persisted: PersistedIdentity =
        toml::from_str(&text).map_err(|e| AetherError::Other(format!("config parse: {e}")))?;
    Identity::try_from(persisted)
}

'''
s = s.replace(old_load, new_load, 1)
open(p, 'w', encoding='utf-8').write(s)
print('load rewritten')
