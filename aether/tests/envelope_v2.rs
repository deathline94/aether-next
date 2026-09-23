//! Config envelope v2: path-bound AEAD, a schema byte, and no plaintext escape.
//!
//! These tests describe behaviour that does not exist yet in the old code: v1
//! authenticated the bytes but not the *location*, and `save()` silently wrote
//! the device id, access token and WireGuard private key in clear text whenever
//! `AETHER_CONFIG_KEY` happened to be unset.

use aether::account::Identity;
use aether::config::{load, save, KeySource};
use aether::runtime_env;
use base64::Engine;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use std::fs;
use std::path::{Path, PathBuf};

/// `Identity` deliberately has no `Debug` (bearer tokens, private keys), so the
/// usual `.expect()` on a value holding one is not available.
fn present<T>(opt: Option<T>, what: &str) -> T {
    match opt {
        Some(v) => v,
        None => panic!("expected {what}"),
    }
}

fn succeeds<T, E: std::fmt::Display>(res: Result<T, E>, what: &str) -> T {
    match res {
        Ok(v) => v,
        Err(e) => panic!("{what}: {e}"),
    }
}

fn fails<E: std::fmt::Display, T>(res: Result<T, E>, what: &str) -> E {
    match res {
        Ok(_) => panic!("{what}: expected an error, got Ok"),
        Err(e) => e,
    }
}

static SERIALISE: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

const KEY: [u8; 32] = [7u8; 32];

fn identity(device: &str) -> Identity {
    Identity {
        device_id: device.into(),
        access_token: "tok".into(),
        cert_pem: vec![],
        key_pem: vec![],
        ipv4: "172.16.0.2".into(),
        ipv6: "2606:4700:110:8751:19d6:4fd1:d894:21dc".into(),
        wg_private_key: [9u8; 32],
        wg_peer_public_key: [10u8; 32],
        client_id: [1u8, 2, 3],
        masque_endpoint: None,
    }
}

fn use_key() {
    runtime_env::set(
        "AETHER_CONFIG_KEY",
        &base64::engine::general_purpose::STANDARD.encode(KEY),
    );
}

fn no_key() {
    runtime_env::remove("AETHER_CONFIG_KEY");
    assert_eq!(aether::config::key_source(), KeySource::None);
}

struct Dir(PathBuf);
impl Dir {
    fn new(tag: &str) -> Self {
        let path = std::env::temp_dir().join(format!("aether_env2_{tag}_{}", std::process::id()));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).expect("temp dir");
        Self(path)
    }
    fn file(&self, name: &str) -> String {
        self.0.join(name).to_string_lossy().to_string()
    }
}
impl Drop for Dir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn legacy_plaintext(path: &str, device: &str) {
    // Exactly what an install from before the envelope looked like.
    let b64 = base64::engine::general_purpose::STANDARD;
    let text = format!(
        "device_id = \"{device}\"\naccess_token = \"tok\"\nipv4 = \"172.16.0.2\"\nipv6 = \"2606:4700:110:8751:19d6:4fd1:d894:21dc\"\nwg_private_key = \"{}\"\nwg_peer_public_key = \"{}\"\n",
        b64.encode([9u8; 32]),
        b64.encode([10u8; 32]),
    );
    fs::write(path, text).expect("write legacy plaintext");
}

#[test]
fn save_refuses_to_write_secret_material_without_a_key() {
    let _g = SERIALISE.lock();
    let dir = Dir::new("nokey");
    let path = dir.file("aether.toml");
    no_key();

    let err = fails(
        save(&path, &identity("dev")),
        "plaintext must not be written",
    );
    let msg = err.to_string();
    assert!(
        msg.contains("AETHER_CONFIG_KEY"),
        "the error must say how to get a key: {msg}"
    );
    assert!(!Path::new(&path).exists(), "no plaintext may reach disk");
}

#[test]
fn a_copied_envelope_fails_authentication_at_the_other_path() {
    let _g = SERIALISE.lock();
    let dir = Dir::new("aad");
    let a = dir.file("aether.toml");
    let b = dir.file("aether-masque.toml");
    use_key();

    save(&a, &identity("device-A")).expect("save A");
    let raw = fs::read(&a).expect("read A");
    assert!(
        raw.starts_with(b"AETHERCFG2\n"),
        "v2 magic expected, got {raw:?}"
    );
    assert_eq!(raw[b"AETHERCFG2\n".len()], 1, "schema version byte");

    // The v1 shape had no AAD, so this copy authenticated perfectly and the
    // identity simply moved house.
    fs::write(&b, &raw).expect("plant copy");
    let err = fails(load(&b), "the same ciphertext must not be valid elsewhere");
    assert!(
        err.to_string().contains("authentication"),
        "expected an authentication failure, got {err}"
    );
    no_key();
}

#[test]
fn each_config_file_gets_its_own_key_stream() {
    let _g = SERIALISE.lock();
    let dir = Dir::new("nonce");
    let a = dir.file("aether.toml");
    let b = dir.file("b.toml");
    use_key();
    save(&a, &identity("same")).expect("a");
    save(&b, &identity("same")).expect("b");
    assert_ne!(
        fs::read(&a).unwrap(),
        fs::read(&b).unwrap(),
        "nonce reuse across files"
    );
    no_key();
}

#[test]
fn a_v1_envelope_still_opens_and_is_upgraded_in_place() {
    let _g = SERIALISE.lock();
    let dir = Dir::new("v1");
    let path = dir.file("aether.toml");
    use_key();

    let plain = format!(
        "device_id = \"legacy-v1\"\naccess_token = \"tok\"\nipv4 = \"172.16.0.2\"\nipv6 = \"2606:4700:110:8751:19d6:4fd1:d894:21dc\"\nwg_private_key = \"{}\"\nwg_peer_public_key = \"{}\"\n",
        base64::engine::general_purpose::STANDARD.encode([9u8; 32]),
        base64::engine::general_purpose::STANDARD.encode([10u8; 32]),
    );
    let cipher = ChaCha20Poly1305::new((&KEY).into());
    let nonce = [3u8; 12];
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce), plain.as_bytes())
        .expect("seal v1");
    let mut blob = b"AETHERCFG1\n".to_vec();
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&ct);
    fs::write(&path, blob).expect("write v1");

    let id = present(succeeds(load(&path), "v1 must still load"), "an identity");
    assert_eq!(id.device_id, "legacy-v1");
    assert!(
        fs::read(&path).unwrap().starts_with(b"AETHERCFG2\n"),
        "reading a v1 file must upgrade it"
    );
    let again = present(
        succeeds(load(&path), "upgrade must be readable"),
        "an identity",
    );
    assert_eq!(again.device_id, "legacy-v1", "upgrade must be readable");
    no_key();
}

#[test]
fn plaintext_is_migrated_and_the_result_is_read_back() {
    let _g = SERIALISE.lock();
    let dir = Dir::new("migrate");
    let path = dir.file("aether.toml");
    legacy_plaintext(&path, "plain-dev");
    use_key();

    let id = present(succeeds(load(&path), "migrate"), "an identity");
    assert_eq!(id.device_id, "plain-dev");
    assert!(fs::read(&path).unwrap().starts_with(b"AETHERCFG2\n"));
    no_key();
}

#[test]
fn plaintext_without_a_key_is_refused_rather_than_accepted_forever() {
    let _g = SERIALISE.lock();
    let dir = Dir::new("plainnokey");
    let path = dir.file("aether.toml");
    legacy_plaintext(&path, "stuck");
    no_key();

    let err = fails(load(&path), "plaintext must not be a stable state");
    assert!(err.to_string().contains("AETHER_CONFIG_KEY"), "{err}");
    assert!(
        Path::new(&path).exists(),
        "the file is preserved for the user to migrate"
    );
}

#[test]
fn a_planted_backup_is_quarantined_and_never_becomes_the_identity() {
    let _g = SERIALISE.lock();
    let dir = Dir::new("bak");
    let path = dir.file("aether.toml");
    let bak = format!("{path}.bak");
    use_key();

    save(&path, &identity("real")).expect("save real");
    // An attacker (or an old crash) leaves a different identity at the backup
    // name; loading must not adopt it.
    fs::write(&bak, fs::read(&path).expect("read real")).expect("plant");
    save(&bak, &identity("impostor")).expect("save impostor to bak");

    let id = present(succeeds(load(&path), "load"), "an identity");
    assert_eq!(
        id.device_id, "real",
        "the backup must never override the live config"
    );
    assert!(
        !Path::new(&bak).exists(),
        "the backup must be moved out of the way"
    );
    assert!(
        Path::new(&format!("{path}.quarantined")).exists(),
        "and kept for inspection"
    );
    no_key();
}
