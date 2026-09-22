//! DPAPI / OS-keyring access for the configuration master key.
//!
//! Declared `pub mod dpapi` from the crate root so the shipped path
//! (`aether_desktop_lib::dpapi`) is unchanged; `super::restrict_directory_acl`
//! below is the crate root.

use crate::CommandError;

use std::path::Path;
use zeroize::Zeroize;

#[cfg(windows)]
use std::ptr;
#[cfg(windows)]
use windows_sys::Win32::Foundation::LocalFree;
#[cfg(windows)]
use windows_sys::Win32::Security::Cryptography::{
    CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
};

/// Which OS secret store can wrap the master key right now.
///
/// The point of naming it is that the wrapping is then a *choice made in one
/// place*. Until now the off-Windows `encrypt`/`decrypt` were the identity
/// function, so "encrypted at rest" was true on one platform and false
/// everywhere else — and the tests that would have shown it are all
/// `#[cfg(windows)]`, so the failure was invisible by construction.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum KeyService {
    /// Windows Data Protection API, scoped to the current user and process.
    #[cfg(windows)]
    Dpapi,
    /// Nothing available: an honest `None`, not a silent pass-through.
    None,
}

pub fn service() -> KeyService {
    #[cfg(windows)]
    {
        KeyService::Dpapi
    }
    #[cfg(not(windows))]
    {
        // Keychain (macOS) and libsecret (Linux) are the remaining sources —
        // specs/015 T096. Adding them means adding a variant here and a real
        // arm below; there is no path that stores a key unwrapped.
        KeyService::None
    }
}

fn no_key_service() -> CommandError {
    CommandError::new(
        "key_service_unavailable",
        "this platform has no OS-backed secret store, and the configuration master key is \
         never written unwrapped; run on Windows or add the Keychain/libsecret key source",
    )
}

pub fn encrypt_with(data: &[u8], svc: KeyService) -> Result<Vec<u8>, CommandError> {
    match svc {
        #[cfg(windows)]
        KeyService::Dpapi => {
            let in_blob = CRYPT_INTEGER_BLOB {
                cbData: data.len() as u32,
                pbData: data.as_ptr() as *mut u8,
            };
            let mut out_blob = CRYPT_INTEGER_BLOB {
                cbData: 0,
                pbData: ptr::null_mut(),
            };

            let res = unsafe {
                CryptProtectData(
                    &in_blob,
                    ptr::null(),
                    ptr::null(),
                    ptr::null(),
                    ptr::null(),
                    CRYPTPROTECT_UI_FORBIDDEN,
                    &mut out_blob,
                )
            };

            if res == 0 {
                let err = std::io::Error::last_os_error();
                return Err(format!("CryptProtectData failed: {err}").into());
            }

            let encrypted = unsafe {
                std::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize).to_vec()
            };

            unsafe {
                LocalFree(out_blob.pbData as _);
            }

            Ok(encrypted)
        }
        KeyService::None => Err(no_key_service()),
    }
}

pub fn decrypt_with(data: &[u8], svc: KeyService) -> Result<Vec<u8>, CommandError> {
    match svc {
        #[cfg(windows)]
        KeyService::Dpapi => {
            let in_blob = CRYPT_INTEGER_BLOB {
                cbData: data.len() as u32,
                pbData: data.as_ptr() as *mut u8,
            };
            let mut out_blob = CRYPT_INTEGER_BLOB {
                cbData: 0,
                pbData: ptr::null_mut(),
            };

            let res = unsafe {
                CryptUnprotectData(
                    &in_blob,
                    ptr::null_mut(),
                    ptr::null(),
                    ptr::null(),
                    ptr::null(),
                    CRYPTPROTECT_UI_FORBIDDEN,
                    &mut out_blob,
                )
            };

            if res == 0 {
                let err = std::io::Error::last_os_error();
                return Err(format!("CryptUnprotectData failed: {err}").into());
            }

            let decrypted = unsafe {
                std::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize).to_vec()
            };

            unsafe {
                if !out_blob.pbData.is_null() && out_blob.cbData > 0 {
                    let slice =
                        std::slice::from_raw_parts_mut(out_blob.pbData, out_blob.cbData as usize);
                    slice.zeroize();
                }
                LocalFree(out_blob.pbData as _);
            }

            Ok(decrypted)
        }
        KeyService::None => Err(no_key_service()),
    }
}

pub fn encrypt(data: &[u8]) -> Result<Vec<u8>, CommandError> {
    encrypt_with(data, service())
}

pub fn decrypt(data: &[u8]) -> Result<Vec<u8>, CommandError> {
    decrypt_with(data, service())
}

const DPAPI_MAGIC: &[u8] = b"DP01";

/// Derives or retrieves the 32-byte DPAPI-protected configuration master key.
/// Returns the base64-encoded string representation for `AETHER_CONFIG_KEY`.
pub fn get_or_create_dpapi_config_key(app_data_dir: &Path) -> Result<String, CommandError> {
    use base64::Engine;
    let key_file = app_data_dir.join("config_key.dpapi");
    if key_file.exists() {
        let raw = std::fs::read(&key_file)
            .map_err(|e| format!("failed reading {}: {e}", key_file.display()))?;
        if !raw.starts_with(DPAPI_MAGIC) {
            return Err(format!(
                "invalid DPAPI key envelope header in {}",
                key_file.display()
            )
            .into());
        }
        let mut decrypted = decrypt(&raw[DPAPI_MAGIC.len()..])?;
        if decrypted.len() != 32 {
            decrypted.zeroize();
            return Err("decrypted master key must be 32 bytes".into());
        }
        let b64 = base64::engine::general_purpose::STANDARD.encode(&decrypted);
        decrypted.zeroize();
        return Ok(b64);
    }

    // Generate new 32-byte key
    let mut raw_key = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut raw_key);

    let ciphertext = encrypt(&raw_key)?;
    let mut envelope = Vec::with_capacity(DPAPI_MAGIC.len() + ciphertext.len());
    envelope.extend_from_slice(DPAPI_MAGIC);
    envelope.extend_from_slice(&ciphertext);

    let tmp_file = app_data_dir.join(format!(
        "config_key.dpapi.{}.{}.tmp",
        std::process::id(),
        rand::random::<u32>()
    ));
    std::fs::create_dir_all(app_data_dir)
        .map_err(|e| format!("cannot create dir {}: {e}", app_data_dir.display()))?;
    {
        // Created exclusively and, off Windows, owner-only from the first
        // byte: `restrict_directory_acl` is a no-op there, so without an
        // explicit mode the master key landed with the process umask
        // (0644 is the common case) while `encrypt()` was the identity
        // function — every user on the machine could read the thing that
        // decrypts every identity on disk.
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&tmp_file)
                .map_err(|e| format!("cannot write {}: {e}", tmp_file.display()))?;
            std::io::Write::write_all(&mut f, &envelope)
                .map_err(|e| format!("cannot write {}: {e}", tmp_file.display()))?;
            f.sync_all()
                .map_err(|e| format!("cannot flush {}: {e}", tmp_file.display()))?;
        }
        #[cfg(not(unix))]
        {
            let mut opts = std::fs::OpenOptions::new();
            opts.write(true).create_new(true);
            let mut f = opts
                .open(&tmp_file)
                .map_err(|e| format!("cannot write {}: {e}", tmp_file.display()))?;
            std::io::Write::write_all(&mut f, &envelope)
                .map_err(|e| format!("cannot write {}: {e}", tmp_file.display()))?;
            f.sync_all()
                .map_err(|e| format!("cannot flush {}: {e}", tmp_file.display()))?;
        }
    }
    // Restrict ACL on the tmp file before rename; fail closed and cleanup on failure
    if let Err(e) = super::restrict_directory_acl(&tmp_file) {
        let _ = std::fs::remove_file(&tmp_file);
        return Err(format!("cannot restrict ACL on {}: {e}", tmp_file.display()).into());
    }

    if let Err(e) = std::fs::rename(&tmp_file, &key_file) {
        let _ = std::fs::remove_file(&tmp_file);
        return Err(format!("cannot rename to {}: {e}", key_file.display()).into());
    }

    // The temp file's DACL travels with the rename, so this repeats a
    // restriction that is normally already in place — and repeating it while
    // *discarding* the result (`let _ =`) was the defect: where the directory
    // re-inherits over the file's own DACL, a failure here was silently the
    // difference between "this user can read the master key" and "everyone
    // can", against a comment that says fail closed. Report it, but leave the
    // file in place: deleting a DPAPI master key the user may already have
    // identities wrapped under is a worse loss than a loud failure.
    super::restrict_directory_acl(&key_file)?;

    let b64 = base64::engine::general_purpose::STANDARD.encode(raw_key);
    raw_key.zeroize();
    Ok(b64)
}
