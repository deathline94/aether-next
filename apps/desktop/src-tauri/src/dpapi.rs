//! DPAPI / OS-keyring access for the configuration master key.
//!
//! Declared `pub mod dpapi` from the crate root so the shipped path
//! (`aether_desktop_lib::dpapi`) is unchanged; `super::restrict_directory_acl`
//! below is the crate root.

use crate::CommandError;

use std::path::Path;
#[cfg(any(windows, test))]
use std::time::Duration;
use zeroize::{Zeroize, Zeroizing};

#[cfg(windows)]
use std::ptr;
#[cfg(all(windows, test))]
use windows_sys::Win32::Foundation as win;
#[cfg(windows)]
use windows_sys::Win32::Foundation::LocalFree;
#[cfg(windows)]
use windows_sys::Win32::Security::Cryptography::{
    CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
};

/// How many times a DPAPI call is attempted before the failure is surfaced, and
/// how long to wait before attempts 2 and 3.
#[cfg(any(windows, test))]
const DPAPI_ATTEMPTS: u32 = 3;
#[cfg(any(windows, test))]
const DPAPI_BACKOFF: [Duration; 2] = [Duration::from_millis(60), Duration::from_millis(240)];

/// What a crypt32 failure means for the file on disk.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DpapiFailure {
    /// A property of the moment — provider busy, share violation, no logon
    /// session yet. Worth another try, and never a reason to touch the envelope.
    Retryable,
    /// A statement about the bytes, or an unknown: the same input gives the same
    /// answer forever, so retrying is only a delay before the same error.
    Fatal,
}

/// Classify a `GetLastError()` code from a crypt32 call.
///
/// FR-014 asks that a transient platform crypto failure be retried and then
/// surfaced rather than treated as corruption. The default is `Fatal` on purpose:
/// guessing that an unrecognised code will pass on the second try buys a retry
/// loop in front of a permanent failure, and the interesting bug is the other one
/// — a real "this profile's master key is gone" retried three times and then
/// reported as a timeout.
pub fn classify_dpapi(code: u32) -> DpapiFailure {
    // Transient because each of these describes the machine, not the bytes: the
    // provider is busy or out of memory, the DPAPI key directory is held by
    // another process doing exactly this, the profile is not mapped yet (a
    // service started before logon, a fast user switch), or the crypto work —
    // which LSASS does over RPC — has no endpoint registered yet.
    const TRANSIENT: &[u32] = &[
        ERROR_TOO_MANY_OPEN_FILES,
        ERROR_ACCESS_DENIED,
        ERROR_NOT_ENOUGH_MEMORY,
        ERROR_OUTOFMEMORY,
        ERROR_SHARING_VIOLATION,
        ERROR_LOCK_VIOLATION,
        RPC_S_SERVER_UNAVAILABLE,
        EPT_S_NOT_REGISTERED,
        NTE_FAIL,
        CRYPT_E_NO_KEY_PROVIDER,
    ];
    if TRANSIENT.contains(&code) {
        return DpapiFailure::Retryable;
    }
    // Everything else, which includes NTE_BAD_DATA (0x80090005), NTE_BAD_HASH,
    // NTE_BAD_LEN, NTE_BAD_SIGNATURE, NTE_BAD_KEYSET, CRYPT_E_BAD_MSG,
    // CRYPT_E_INVALID_MAC and TRUST_E_BAD_DIGEST: each is the provider saying
    // *this blob* is bad, which no retry and no second copy of the same bytes
    // will change.
    DpapiFailure::Fatal
}

/// Win32 error codes, RPC codes and NTSTATUS/HRESULT crypto codes, written as
/// numbers under their documented names so the table compiles — and is unit
/// tested — on every platform instead of hiding behind a `windows-sys` feature
/// gate. `transcribed_codes_match_the_windows_headers` pins the Win32 half
/// against the real headers wherever they are available.
const ERROR_TOO_MANY_OPEN_FILES: u32 = 4;
const ERROR_ACCESS_DENIED: u32 = 5;
const ERROR_NOT_ENOUGH_MEMORY: u32 = 8;
const ERROR_OUTOFMEMORY: u32 = 14;
const ERROR_SHARING_VIOLATION: u32 = 32;
const ERROR_LOCK_VIOLATION: u32 = 33;
const RPC_S_SERVER_UNAVAILABLE: u32 = 1722;
const EPT_S_NOT_REGISTERED: u32 = 1754;
const NTE_FAIL: u32 = 0x8009_0029;
const CRYPT_E_NO_KEY_PROVIDER: u32 = 0x8009_100B;

/// The error surfaced after the retries, typed so the UI can say "try again"
/// rather than "your identity is gone" — and so that neither wording is a lie.
#[cfg(any(windows, test))]
fn dpapi_error(name: &str, code: u32, attempts: u32) -> CommandError {
    let detail = std::io::Error::from_raw_os_error(code as i32).to_string();
    match classify_dpapi(code) {
        DpapiFailure::Retryable => CommandError::new(
            "key_service_unavailable",
            format!(
                "{name} failed {attempts} times: {detail} ({code:#010x}). This is a temporary \
                 failure of the OS key service; the stored master key has not been touched. \
                 Reconnect, or sign out and in again if it persists."
            ),
        ),
        DpapiFailure::Fatal => CommandError::new(
            "key_service_rejected",
            format!(
                "{name} rejected the stored master key: {detail} ({code:#010x}). The envelope is \
                 left in place, unread and undeleted, because identities may already be wrapped \
                 under it."
            ),
        ),
    }
}

/// Run one crypt32 call through the retry budget. `once` returns the raw
/// last-error code with `Err`, already captured at the call site.
#[cfg(any(windows, test))]
fn dpapi_attempt<T>(
    name: &str,
    mut once: impl FnMut() -> Result<T, u32>,
) -> Result<T, CommandError> {
    let mut attempt = 0u32;
    loop {
        attempt += 1;
        match once() {
            Ok(v) => return Ok(v),
            Err(code) => {
                if attempt >= DPAPI_ATTEMPTS || classify_dpapi(code) == DpapiFailure::Fatal {
                    return Err(dpapi_error(name, code, attempt));
                }
                std::thread::sleep(DPAPI_BACKOFF[(attempt as usize) - 1]);
            }
        }
    }
}

/// The thread's last-error value as crypt32 left it. Read through `std` rather
/// than a fresh `windows_sys` binding because this is the same accessor the
/// pre-retry code used: the classification must not be able to break on an
/// import, and a truncated `i32` restores the NTSTATUS/HRESULT bit pattern
/// exactly.
#[cfg(any(windows, test))]
fn last_crypto_error() -> u32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0) as u32
}

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
            dpapi_attempt("CryptProtectData", || {
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
                    return Err(last_crypto_error());
                }
                let encrypted = unsafe {
                    std::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize).to_vec()
                };
                unsafe { LocalFree(out_blob.pbData as _) };
                Ok(encrypted)
            })
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
            dpapi_attempt("CryptUnprotectData", || {
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
                    return Err(last_crypto_error());
                }
                let decrypted = unsafe {
                    std::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize).to_vec()
                };
                unsafe {
                    if !out_blob.pbData.is_null() && out_blob.cbData > 0 {
                        let slice = std::slice::from_raw_parts_mut(
                            out_blob.pbData,
                            out_blob.cbData as usize,
                        );
                        slice.zeroize();
                    }
                    LocalFree(out_blob.pbData as _);
                };
                Ok(decrypted)
            })
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
        let decrypted = Zeroizing::new(decrypt(&raw[DPAPI_MAGIC.len()..])?);
        if decrypted.len() != 32 {
            // Wrong length is a fact about the bytes, not a bad moment: the file
            // is reported and left alone, because whatever it is, it is the only
            // copy of the thing that decrypts the identities on this disk.
            return Err(CommandError::new(
                "key_service_rejected",
                format!(
                    "the stored master key unwraps to {} bytes, not 32; {} is left in place",
                    decrypted.len(),
                    key_file.display()
                ),
            ));
        }
        return Ok(base64::engine::general_purpose::STANDARD.encode(&*decrypted));
    }

    // Generate new 32-byte key. `Zeroizing` rather than a manual `zeroize()` at
    // the bottom: half of the paths out of this function are `?`, and a stack
    // array has no Drop, so every early return used to leave a master key sitting
    // in the frame of a process that keeps running.
    let mut raw_key = Zeroizing::new([0u8; 32]);
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut *raw_key);

    let ciphertext = encrypt(&*raw_key)?;
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

    let encoded = base64::engine::general_purpose::STANDARD.encode(&raw_key[..]);
    Ok(encoded)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bad_moment_is_told_apart_from_bad_bytes() {
        for code in [
            ERROR_SHARING_VIOLATION,
            ERROR_LOCK_VIOLATION,
            ERROR_OUTOFMEMORY,
            RPC_S_SERVER_UNAVAILABLE,
            EPT_S_NOT_REGISTERED,
            NTE_FAIL,
            CRYPT_E_NO_KEY_PROVIDER,
        ] {
            assert_eq!(
                classify_dpapi(code),
                DpapiFailure::Retryable,
                "{code:#010x} is a property of the machine, not of the envelope"
            );
        }
        for code in [
            0x8009_0005u32, // NTE_BAD_DATA
            0x8009_100A,    // CRYPT_E_BAD_MSG
            0x8009_2004,    // CRYPT_E_INVALID_MAC
            0x0000_0002,    // ERROR_FILE_NOT_FOUND
            0xDEAD_BEEF,    // unrecognised: never retried
        ] {
            assert_eq!(
                classify_dpapi(code),
                DpapiFailure::Fatal,
                "{code:#010x} is a statement about the bytes"
            );
        }
    }

    #[test]
    fn the_retry_budget_spends_itself_on_a_transient_and_not_on_a_corrupt() {
        let mut calls = 0;
        let err = dpapi_attempt("CryptUnprotectData", || {
            calls += 1;
            Err::<(), u32>(ERROR_SHARING_VIOLATION)
        })
        .expect_err("a call that always fails cannot succeed");
        assert_eq!(calls, DPAPI_ATTEMPTS, "a transient failure is retried");
        assert_eq!(err.code, "key_service_unavailable");
        assert!(
            err.message.contains("has not been touched"),
            "the surfaced error has to say the envelope is intact: {err:?}"
        );

        let mut calls = 0;
        let err = dpapi_attempt("CryptUnprotectData", || {
            calls += 1;
            Err::<(), u32>(0x8009_0005)
        })
        .expect_err("a corrupt blob does not become valid");
        assert_eq!(calls, 1, "a fatal failure is not sat on for 300 ms");
        assert_eq!(err.code, "key_service_rejected");

        let mut calls = 0;
        let ok = dpapi_attempt("CryptProtectData", || {
            calls += 1;
            Ok(vec![7u8])
        })
        .expect("a succeeding call is not retried");
        assert_eq!(ok, vec![7]);
        assert_eq!(calls, 1);
    }

    /// The numbers in this module are transcribed from the Windows headers
    /// because the table has to compile on every platform; this is what stops a
    /// transcription error from quietly turning a security decision into a retry.
    #[cfg(windows)]
    #[test]
    fn transcribed_codes_match_the_windows_headers() {
        assert_eq!(ERROR_TOO_MANY_OPEN_FILES, win::ERROR_TOO_MANY_OPEN_FILES);
        assert_eq!(ERROR_ACCESS_DENIED, win::ERROR_ACCESS_DENIED);
        assert_eq!(ERROR_NOT_ENOUGH_MEMORY, win::ERROR_NOT_ENOUGH_MEMORY);
        assert_eq!(ERROR_OUTOFMEMORY, win::ERROR_OUTOFMEMORY);
        assert_eq!(ERROR_SHARING_VIOLATION, win::ERROR_SHARING_VIOLATION);
        assert_eq!(ERROR_LOCK_VIOLATION, win::ERROR_LOCK_VIOLATION);
    }

    // The live-DPAPI round trip — wrap a key, mutate the envelope, prove the file
    // survives the failure — is the test FR-014 really wants, and it is not here,
    // for a measured reason rather than a guessed one: referencing
    // `get_or_create_dpapi_config_key` from this crate's test binary makes the
    // *whole* binary fail to load on the GNU toolchain
    // (`STATUS_ENTRYPOINT_NOT_FOUND`, before a single test runs), so shipping it
    // would trade every other shell test in this crate for one. What it would
    // have asserted — that no code path destroys `config_key.dpapi` — is held by
    // the `master-key-never-destroyed` gate in `scripts/verify-invariants.mjs`,
    // which runs everywhere. The retry budget and the transient/corrupt split,
    // which is the half this module actually decides, are tested above.
}
