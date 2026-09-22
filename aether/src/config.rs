use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};

use base64::Engine;
use chacha20poly1305::aead::KeyInit;
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::account::Identity;
use crate::error::{AetherError, Result};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
    #[serde(default)]
    pub masque_endpoint: Option<String>,
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
            masque_endpoint: id.masque_endpoint.clone(),
        }
    }
}

impl TryFrom<PersistedIdentity> for Identity {
    type Error = AetherError;

    fn try_from(p: PersistedIdentity) -> Result<Self> {
        let wg_priv = decode_key(&p.wg_private_key, "wg private key")?;
        let wg_peer = decode_key(&p.wg_peer_public_key, "wg peer public key")?;
        let mut wg_private_key = [0u8; 32];
        let mut wg_peer_public_key = [0u8; 32];
        wg_private_key.copy_from_slice(&wg_priv);
        wg_peer_public_key.copy_from_slice(&wg_peer);

        let mut client_id_arr = [0u8; 3];
        if !p.client_id.is_empty() {
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(&p.client_id)
                .map_err(|e| AetherError::Other(format!("decode client id: {e}")))?;
            if decoded.len() != 3 {
                return Err(AetherError::Other(format!(
                    "client id length {} (want 3)",
                    decoded.len()
                )));
            }
            client_id_arr.copy_from_slice(&decoded);
        }

        // Address fields become parsed types here. They used to be carried as
        // `String` all the way into packet construction, so a corrupted config
        // produced a malformed tunnel rather than a rejection at load time.
        let ipv4: Ipv4Addr = p
            .ipv4
            .trim()
            .parse()
            .map_err(|e| AetherError::Other(format!("invalid ipv4 address {:?}: {e}", p.ipv4)))?;
        let ipv6: Ipv6Addr = p
            .ipv6
            .trim()
            .parse()
            .map_err(|e| AetherError::Other(format!("invalid ipv6 address {:?}: {e}", p.ipv6)))?;
        let masque_endpoint = match p.masque_endpoint.as_deref() {
            None => None,
            Some(raw) => {
                let raw = raw.trim();
                if raw.is_empty() {
                    None
                } else {
                    let addr: SocketAddr = raw
                        .parse()
                        .map_err(|e| {
                            AetherError::Other(format!("invalid masque endpoint {raw:?}: {e}"))
                        })?;
                    Some(addr.to_string())
                }
            }
        };

        Ok(Identity {
            device_id: p.device_id,
            access_token: p.access_token,
            cert_pem: p.cert_pem.into_bytes(),
            key_pem: p.key_pem.into_bytes(),
            ipv4: ipv4.to_string(),
            ipv6: ipv6.to_string(),
            wg_private_key,
            wg_peer_public_key,
            client_id: client_id_arr,
            masque_endpoint,
        })
    }
}

fn decode_key(value: &str, label: &str) -> Result<[u8; 32]> {
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(value)
        .map_err(|e| AetherError::Other(format!("decode {label}: {e}")))?;
    if decoded.len() != 32 {
        return Err(AetherError::Other(format!(
            "{label} length {} (want 32)",
            decoded.len()
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&decoded);
    Ok(out)
}

const MAX_CONFIG_BYTES: u64 = 1024 * 1024;
/// Version 1 wrapped the payload with a nonce but no additional authenticated
/// data, so one file's ciphertext was valid at *any* path. Kept only to open
/// existing installs; every write produces v2.
const MAGIC_V1: &[u8] = b"AETHERCFG1\n";
/// v2 = `AETHERCFG2\n` | schema: u8 | nonce: 12 | ciphertext+tag, with the
/// canonicalised file path as additional authenticated data.
const MAGIC_V2: &[u8] = b"AETHERCFG2\n";
const SCHEMA_VERSION: u8 = 1;
const NONCE_LEN: usize = 12;

/// Where the envelope key came from. The engine never holds a key hierarchy of
/// its own: the shell resolves DPAPI / AndroidKeyStore / Keychain / libsecret
/// and hands the 32 bytes over. What the engine *can* say is whether it got one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeySource {
    Injected,
    None,
}

pub fn key_source() -> KeySource {
    match crate::runtime_env::var("AETHER_CONFIG_KEY") {
        Some(v) if !v.trim().is_empty() => KeySource::Injected,
        _ => KeySource::None,
    }
}

fn key() -> Result<Option<[u8; 32]>> {
    let Some(v) = crate::runtime_env::var("AETHER_CONFIG_KEY") else {
        return Ok(None);
    };
    let v = v.trim().to_string();
    if v.is_empty() {
        return Ok(None);
    }
    let b = base64::engine::general_purpose::STANDARD
        .decode(&v)
        .map_err(|_| AetherError::Other("invalid config key encoding".into()))?;
    if b.len() != 32 {
        return Err(AetherError::Other("config key must be 32 bytes".into()));
    }
    let mut k = [0u8; 32];
    k.copy_from_slice(&b);
    Ok(Some(k))
}

/// The path this envelope is bound to, in a spelling that survives a `cd`.
///
/// Without it, copying `aether-masque.toml`'s ciphertext over `aether.toml`
/// authenticated perfectly — the same key, the same plaintext, and the identity
/// (device id, token, WireGuard private key) cloned onto another config.
fn path_aad(path: &str) -> Vec<u8> {
    let p = Path::new(path);
    let parent = p.parent().unwrap_or_else(|| Path::new(""));
    let canonical: PathBuf = parent.canonicalize().unwrap_or_else(|_| parent.to_path_buf());
    let mut out: Vec<u8> = Vec::with_capacity(64);
    out.extend_from_slice(canonical.as_os_str().as_encoded_bytes());
    out.push(0);
    if let Some(name) = p.file_name() {
        out.extend_from_slice(name.as_encoded_bytes());
    }
    if cfg!(windows) {
        // NTFS names are case-insensitive: `Aether.toml` and `aether.toml` are
        // the same file, and the bind must not depend on which spelling a
        // caller happened to pass.
        out.make_ascii_lowercase();
    }
    out
}

fn seal(path: &str, plain: &[u8]) -> Result<Vec<u8>> {
    let Some(mut k) = key()? else {
        return Err(AetherError::Other(
            "no configuration key available: refusing to write identity material in plaintext. \
             Launch through the Aether app, or set AETHER_CONFIG_KEY to a base64-encoded 32-byte key."
                .into(),
        ));
    };
    let cipher = ChaCha20Poly1305::new((&k).into());
    let mut nonce = [0u8; NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let aad = path_aad(path);
    let ct = seal_with(&cipher, &nonce, &aad, plain)?;
    k.fill(0);
    let mut out = Vec::with_capacity(MAGIC_V2.len() + 1 + NONCE_LEN + ct.len());
    out.extend_from_slice(MAGIC_V2);
    out.push(SCHEMA_VERSION);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

fn seal_with(
    cipher: &ChaCha20Poly1305,
    nonce: &[u8],
    aad: &[u8],
    plain: &[u8],
) -> Result<Vec<u8>> {
    use chacha20poly1305::aead::AeadInPlace;
    let mut buf = plain.to_vec();
    cipher
        .encrypt_in_place(Nonce::from_slice(nonce), aad, &mut buf)
        .map_err(|_| AetherError::Other("config encryption failed".into()))?;
    Ok(buf)
}

fn open_with(
    cipher: &ChaCha20Poly1305,
    nonce: &[u8],
    aad: &[u8],
    body: &[u8],
) -> Result<Vec<u8>> {
    use chacha20poly1305::aead::AeadInPlace;
    let mut buf = body.to_vec();
    cipher
        .decrypt_in_place(Nonce::from_slice(nonce), aad, &mut buf)
        .map_err(|_| AetherError::Other("config authentication failed".into()))?;
    Ok(buf)
}

/// Returns `None` when the bytes are a pre-envelope plaintext config.
fn open(path: &str, raw: &[u8], k: &[u8; 32]) -> Result<Option<Vec<u8>>> {
    let cipher = ChaCha20Poly1305::new(k.into());
    if let Some(body) = raw.strip_prefix(MAGIC_V2) {
        let Some(&version) = body.first() else {
            return Err(AetherError::Other("truncated config envelope header".into()));
        };
        if version > SCHEMA_VERSION {
            return Err(AetherError::Other(format!(
                "config schema version {version} is newer than this build understands ({SCHEMA_VERSION})"
            )));
        }
        let rest = &body[1..];
        if rest.len() < NONCE_LEN + 16 {
            return Err(AetherError::Other("truncated encrypted config".into()));
        }
        return Ok(Some(open_with(&cipher, &rest[..NONCE_LEN], &path_aad(path), &rest[NONCE_LEN..])?));
    }
    if let Some(body) = raw.strip_prefix(MAGIC_V1) {
        if body.len() < NONCE_LEN + 16 {
            return Err(AetherError::Other("truncated encrypted config".into()));
        }
        // v1 had no AAD; authenticating it is enough to read it, and the caller
        // re-seals it as v2 immediately.
        return Ok(Some(open_with(
            &cipher,
            &body[..NONCE_LEN],
            b"",
            &body[NONCE_LEN..],
        )?));
    }
    Ok(None)
}

/// Test-only seam: forces `restrict_windows_acl` to fail so the fail-closed path
/// is exercised. Behind the `test-hooks` feature so no shipped binary contains a
/// switch that skips the private-file ACL.
#[cfg(any(test, feature = "test-hooks"))]
pub static ACL_FAIL_FOR_TEST: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

#[cfg(windows)]
fn restrict_windows_acl(path: &str) -> Result<()> {
    #[cfg(any(test, feature = "test-hooks"))]
    if ACL_FAIL_FOR_TEST.load(std::sync::atomic::Ordering::SeqCst) {
        return Err(AetherError::Other("forced ACL failure for test".into()));
    }
    let principal = crate::win_acl::current_user_sid()?;
    let exe = crate::win_exec::system_exe("icacls")?;
    let output = std::process::Command::new(&exe)
        .args([path, "/inheritance:r", "/grant:r", &format!("*{principal}:F")])
        .output()
        .map_err(|e| {
            AetherError::Other(format!("failed to run {} on {path}: {e}", exe.display()))
        })?;
    if !output.status.success() {
        let err = String::from_utf8_lossy(&output.stderr);
        return Err(AetherError::Other(format!(
            "icacls failed to restrict permissions on {path}: {}",
            err.trim()
        )));
    }
    Ok(())
}

/// Unix restricts by file mode at create time (0600), so this hook is only
/// called from Windows paths; the stub exists to keep the call sites uniform.
#[cfg(not(windows))]
#[allow(dead_code)]
fn restrict_windows_acl(_path: &str) -> Result<()> {
    Ok(())
}

static TMP_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Unique, exclusively created temp name — a fixed `{path}.{pid}.tmp` lets two
/// processes of the same pid family (or a hostile local user who guessed the
/// name ahead of time) race on one file that carries secret bytes.
fn temp_name(path: &str) -> String {
    let seq = TMP_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let rand: u32 = rand::random();
    format!(
        "{path}.{}.{}.{}.tmp",
        std::process::id(),
        seq,
        rand
    )
}

/// Atomic + locked-down write for secret files (identity TOML, session
/// tickets). The temp file is created empty and exclusively, its ACL is
/// restricted **before** any secret byte hits disk, and the final file is
/// re-restricted after the rename.
pub fn write_private_file(path: &str, data: &[u8]) -> Result<()> {
    if let Some(parent) = Path::new(path).parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = temp_name(path);
    {
        use std::io::Write as _;
        let mut opts = std::fs::OpenOptions::new();
        opts.create_new(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp).map_err(|e| {
            AetherError::Other(format!("cannot create private temp file for {path}: {e}"))
        })?;
        #[cfg(windows)]
        {
            // Nothing has been written yet: restrict first, then write.
            drop(f);
            if let Err(e) = restrict_windows_acl(&tmp) {
                let _ = std::fs::remove_file(&tmp);
                return Err(e);
            }
            f = match std::fs::OpenOptions::new().append(true).open(&tmp) {
                Ok(f) => f,
                Err(e) => {
                    let _ = std::fs::remove_file(&tmp);
                    return Err(e.into());
                }
            };
        }
        if let Err(e) = f.write_all(data).and_then(|()| f.sync_all()) {
            let _ = std::fs::remove_file(&tmp);
            return Err(e.into());
        }
    }

    #[cfg(windows)]
    {
        if Path::new(path).exists() {
            use std::os::windows::ffi::OsStrExt;
            use windows_sys::Win32::Storage::FileSystem::{
                ReplaceFileW, REPLACEFILE_IGNORE_MERGE_ERRORS, REPLACEFILE_WRITE_THROUGH,
            };
            let target_wide: Vec<u16> = Path::new(path)
                .as_os_str()
                .encode_wide()
                .chain(Some(0))
                .collect();
            let tmp_wide: Vec<u16> = Path::new(&tmp)
                .as_os_str()
                .encode_wide()
                .chain(Some(0))
                .collect();
            // `lpBackupFileName = NULL`: a backup copy of the previous identity
            // sitting next to the live file, outside the restricted writer and
            // readable by anything that can read the directory, is a secret
            // leak *and* the thing `load()` used to restore without question.
            let ret = unsafe {
                ReplaceFileW(
                    target_wide.as_ptr(),
                    tmp_wide.as_ptr(),
                    std::ptr::null(),
                    REPLACEFILE_WRITE_THROUGH | REPLACEFILE_IGNORE_MERGE_ERRORS,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            };
            if ret == 0 {
                let err = std::io::Error::last_os_error();
                let _ = std::fs::remove_file(&tmp);
                return Err(AetherError::Other(format!("atomic replace failed: {err}")));
            }
        } else if let Err(e) = std::fs::rename(&tmp, path) {
            let _ = std::fs::remove_file(&tmp);
            return Err(e.into());
        }
        if let Err(e) = restrict_windows_acl(path) {
            let _ = e;
            // The bytes are already in place and ACL-restricted from the temp
            // phase; failing the second pass must not lose the config.
            log::warn!("[config] could not re-restrict ACL on {path}");
        }
    }
    #[cfg(not(windows))]
    {
        std::fs::rename(&tmp, path)?;
        sync_dir(Path::new(path).parent().unwrap_or_else(|| Path::new(".")));
    }
    Ok(())
}

/// Make a rename survive a power loss: the directory entry, not just the file.
#[cfg(all(unix, not(windows)))]
fn sync_dir(dir: &Path) {
    if let Ok(f) = std::fs::File::open(dir) {
        let _ = f.sync_all();
    }
}

/// Move a leftover `<path>.bak` out of the way without ever reading it.
///
/// It used to be the recovery source: whatever landed at `<path>.bak` was
/// copied over the live config with the error ignored, so any local write of
/// that one filename replaced the identity the tunnel authenticates with.
fn quarantine_backup(path: &str) {
    let bak = format!("{path}.bak");
    if !Path::new(&bak).exists() {
        return;
    }
    let doomed = format!("{path}.quarantined");
    match std::fs::rename(&bak, &doomed) {
        Ok(()) => log::error!(
            "[config] ignored and quarantined unauthenticated backup {bak} -> {doomed}"
        ),
        Err(e) => {
            log::error!("[config] could not quarantine {bak}: {e}; removing instead");
            let _ = std::fs::remove_file(&bak);
        }
    }
}

pub fn load(path: &str) -> Result<Option<Identity>> {
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
                "config is stored unencrypted and no key is available to seal it: refusing to keep \
                 identity material in plaintext. Launch through the Aether app or set \
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

pub fn save(path: &str, identity: &Identity) -> Result<()> {
    let persisted = PersistedIdentity::from(identity);
    let text =
        toml::to_string_pretty(&persisted).map_err(|e| AetherError::Other(format!("config encode: {e}")))?;
    let data = seal(path, text.as_bytes())?;
    write_private_file(path, &data)
}

/// Format WireGuard client configuration with AmneziaWG obfuscation parameters.
#[allow(dead_code)]
pub fn format_amnezia_wg_config(
    identity: &Identity,
    peer_endpoint: &str,
    dns: Option<&str>,
) -> String {
    let priv_key = base64::engine::general_purpose::STANDARD.encode(identity.wg_private_key);
    let peer_key = base64::engine::general_purpose::STANDARD.encode(identity.wg_peer_public_key);
    let dns_line = dns.unwrap_or("1.1.1.1");
    format!(
        "[Interface]\n\
         PrivateKey = {priv_key}\n\
         Address = {}/32, {}/128\n\
         DNS = {dns_line}\n\
         Jc = 5\n\
         Jmin = 50\n\
         Jmax = 128\n\
         \n\
         [Peer]\n\
         PublicKey = {peer_key}\n\
         Endpoint = {peer_endpoint}\n\
         AllowedIPs = 0.0.0.0/0, ::/0\n",
        identity.ipv4, identity.ipv6
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_amnezia_wg_config_format() {
        let id = Identity {
            device_id: "test-device".into(),
            access_token: "test-token".into(),
            cert_pem: vec![],
            key_pem: vec![],
            ipv4: "172.16.0.2".into(),
            ipv6: "2606:4700::1".into(),
            wg_private_key: [1u8; 32],
            wg_peer_public_key: [2u8; 32],
            client_id: [0u8; 3],
            masque_endpoint: None,
        };
        let cfg = format_amnezia_wg_config(&id, "162.159.193.1:2408", None);
        assert!(cfg.contains("Jc = 5"));
        assert!(cfg.contains("Jmin = 50"));
        assert!(cfg.contains("Jmax = 128"));
        assert!(cfg.contains("PrivateKey = "));
    }

    #[test]
    fn aad_tracks_the_file_not_its_directory() {
        let a = path_aad("/var/lib/aether/aether.toml");
        let b = path_aad("/var/lib/aether/aether-masque.toml");
        let same = path_aad("/var/lib/aether/aether.toml");
        assert_ne!(a, b, "two configs in one directory must not share a bind");
        assert_eq!(a, same);
    }

    #[test]
    fn unknown_fields_and_bad_addresses_are_rejected_at_load() {
        let mut p = PersistedIdentity {
            device_id: "d".into(),
            access_token: "t".into(),
            cert_pem: String::new(),
            key_pem: String::new(),
            ipv4: "172.16.0.2".into(),
            ipv6: "2606::1".into(),
            wg_private_key: base64::engine::general_purpose::STANDARD.encode([1u8; 32]),
            wg_peer_public_key: base64::engine::general_purpose::STANDARD.encode([2u8; 32]),
            client_id: String::new(),
            masque_endpoint: None,
        };
        assert!(Identity::try_from(p.clone()).is_ok());

        p.ipv4 = "not-an-address".into();
        assert!(Identity::try_from(p.clone()).is_err(), "a corrupt ipv4 must not start a tunnel");

        p.ipv4 = "172.16.0.2".into();
        p.masque_endpoint = Some("162.159.198.2:not-a-port".into());
        assert!(Identity::try_from(p.clone()).is_err(), "endpoint must be a parsed SocketAddr");

        p.masque_endpoint = None;
        p.wg_private_key = "short".into();
        assert!(Identity::try_from(p).is_err(), "a mistyped key must error, not default");
    }
}
