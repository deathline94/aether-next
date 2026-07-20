use std::path::Path;

use base64::Engine;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::account::Identity;
use crate::error::{AetherError, Result};

#[derive(Clone, Serialize, Deserialize)]
pub struct PersistedIdentity {
    pub device_id: String,
    pub access_token: String,
    #[serde(default)]
    pub cert_pem: String,
    #[serde(default)]
    pub key_pem: String,
    pub ipv4: String,
    pub ipv6: String,
    pub wg_private_key: String,
    pub wg_peer_public_key: String,
    #[serde(default)]
    pub client_id: String,
}

impl From<&Identity> for PersistedIdentity {
    fn from(id: &Identity) -> Self {
        Self {
            device_id: id.device_id.clone(),
            access_token: id.access_token.clone(),
            cert_pem: String::from_utf8_lossy(&id.cert_pem).to_string(),
            key_pem: String::from_utf8_lossy(&id.key_pem).to_string(),
            ipv4: id.ipv4.clone(),
            ipv6: id.ipv6.clone(),
            wg_private_key: base64::engine::general_purpose::STANDARD.encode(id.wg_private_key),
            wg_peer_public_key: base64::engine::general_purpose::STANDARD
                .encode(id.wg_peer_public_key),
            client_id: base64::engine::general_purpose::STANDARD.encode(id.client_id),
        }
    }
}

impl TryFrom<PersistedIdentity> for Identity {
    type Error = AetherError;

    fn try_from(p: PersistedIdentity) -> Result<Self> {
        let wg_priv = base64::engine::general_purpose::STANDARD
            .decode(&p.wg_private_key)
            .map_err(|e| AetherError::Other(format!("decode wg private key: {e}")))?;
        let wg_peer = base64::engine::general_purpose::STANDARD
            .decode(&p.wg_peer_public_key)
            .map_err(|e| AetherError::Other(format!("decode wg peer public key: {e}")))?;
        if wg_priv.len() != 32 {
            return Err(AetherError::Other(format!(
                "wg private key length {} (want 32)",
                wg_priv.len()
            )));
        }
        if wg_peer.len() != 32 {
            return Err(AetherError::Other(format!(
                "wg peer public key length {} (want 32)",
                wg_peer.len()
            )));
        }
        let mut wg_private_key = [0u8; 32];
        let mut wg_peer_public_key = [0u8; 32];
        let mut client_id_arr = [0u8; 3];
        wg_private_key.copy_from_slice(&wg_priv);
        wg_peer_public_key.copy_from_slice(&wg_peer);
        if !p.client_id.is_empty() {
            if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(&p.client_id) {
                if decoded.len() == 3 {
                    client_id_arr.copy_from_slice(&decoded);
                }
            }
        }
        Ok(Identity {
            device_id: p.device_id,
            access_token: p.access_token,
            cert_pem: p.cert_pem.into_bytes(),
            key_pem: p.key_pem.into_bytes(),
            ipv4: p.ipv4,
            ipv6: p.ipv6,
            wg_private_key,
            wg_peer_public_key,
            client_id: client_id_arr,
        })
    }
}

const MAX_CONFIG_BYTES: u64 = 1024 * 1024;
const MAGIC: &[u8] = b"AETHERCFG1\n";

fn key() -> Result<Option<[u8; 32]>> {
    let Some(v) = std::env::var_os("AETHER_CONFIG_KEY") else { return Ok(None) };
    let b = base64::engine::general_purpose::STANDARD.decode(v.to_string_lossy().trim())
        .map_err(|_| AetherError::Other("invalid config key".into()))?;
    if b.len() != 32 { return Err(AetherError::Other("config key must be 32 bytes".into())); }
    let mut k=[0u8;32]; k.copy_from_slice(&b); Ok(Some(k))
}
fn encode(plain: &[u8]) -> Result<Vec<u8>> {
    let Some(mut k)=key()? else { return Ok(plain.to_vec()) };
    let cipher=ChaCha20Poly1305::new((&k).into());
    let mut nonce=[0u8;12]; rand::thread_rng().fill_bytes(&mut nonce);
    let ct=cipher.encrypt(Nonce::from_slice(&nonce), plain)
        .map_err(|_| AetherError::Other("config encryption failed".into()))?;
    k.fill(0); let mut out=MAGIC.to_vec(); out.extend_from_slice(&nonce); out.extend_from_slice(&ct); Ok(out)
}
fn read_text(path: &str) -> Result<String> {
    let raw=std::fs::read(path)?;
    let plain=if let Some(body)=raw.strip_prefix(MAGIC) {
        if body.len()<12 { return Err(AetherError::Other("truncated encrypted config".into())); }
        let Some(mut k)=key()? else { return Err(AetherError::Other("encrypted config key unavailable".into())); };
        let cipher=ChaCha20Poly1305::new((&k).into());
        let p=cipher.decrypt(Nonce::from_slice(&body[..12]), &body[12..])
            .map_err(|_| AetherError::Other("config authentication failed".into()))?;
        k.fill(0); p
    } else { raw };
    String::from_utf8(plain).map_err(|_| AetherError::Other("invalid config encoding".into()))
}
fn private_atomic_write(path: &str, data: &[u8]) -> Result<()> {
    if let Some(parent)=Path::new(path).parent() { std::fs::create_dir_all(parent)?; }
    let tmp=format!("{path}.tmp");
    #[cfg(unix)] {
        use std::fs::OpenOptions; use std::io::Write; use std::os::unix::fs::OpenOptionsExt;
        let mut f=OpenOptions::new().create(true).truncate(true).write(true).mode(0o600).open(&tmp)?;
        f.write_all(data)?; f.sync_all()?;
    }
    #[cfg(not(unix))] std::fs::write(&tmp,data)?;
    if Path::new(path).exists() { std::fs::remove_file(path)?; }
    std::fs::rename(&tmp,path)?;
    #[cfg(windows)] if let Ok(user)=std::env::var("USERNAME") {
        let _=std::process::Command::new("icacls").args([path,"/inheritance:r","/grant:r",&format!("{user}:F")]).output();
    }
    Ok(())
}

pub fn load(path: &str) -> Result<Option<Identity>> {
    if !Path::new(path).exists() {
        return Ok(None);
    }
    let meta = std::fs::metadata(path)?;
    if meta.len() > MAX_CONFIG_BYTES {
        return Err(AetherError::Other(format!(
            "config too large ({} bytes)",
            meta.len()
        )));
    }
    let text = read_text(path)?;
    let persisted: PersistedIdentity =
        toml::from_str(&text).map_err(|e| AetherError::Other(format!("config parse: {e}")))?;
    Ok(Some(Identity::try_from(persisted)?))
}

pub fn save(path: &str, identity: &Identity) -> Result<()> {
    let persisted = PersistedIdentity::from(identity);
    let text = toml::to_string_pretty(&persisted)
        .map_err(|e| AetherError::Other(format!("config encode: {e}")))?;
    let data=encode(text.as_bytes())?;
    private_atomic_write(path, &data)
}

pub fn save_masque_creds(path: &str, cert_pem: &[u8], key_pem: &[u8]) -> Result<()> {
    if !Path::new(path).exists() {
        return Ok(());
    }
    let text = read_text(path)?;
    let mut persisted: PersistedIdentity =
        toml::from_str(&text).map_err(|e| AetherError::Other(format!("config parse: {e}")))?;
    persisted.cert_pem = String::from_utf8_lossy(cert_pem).to_string();
    persisted.key_pem = String::from_utf8_lossy(key_pem).to_string();
    let updated = toml::to_string_pretty(&persisted)
        .map_err(|e| AetherError::Other(format!("config encode: {e}")))?;
    let data=encode(updated.as_bytes())?;
    private_atomic_write(path, &data)
}
