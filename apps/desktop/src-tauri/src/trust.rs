//! Binary trust: which files may be executed at all, what their digest and
//! signing certificate have to look like, and the committed anchor those answers
//! come from.
//!
//! The tables below are compiled from `packaging/trust/engine-trust.json` by
//! `build.rs` — never computed from the artifact being shipped, which is what made
//! the comparison unable to fail.
use crate::error::CommandError;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

/// TUN runs elevated: only load regular files under the app install / portable root.
pub fn validate_trusted_binary(path: &PathBuf, label: &str) -> Result<(), CommandError> {
    // `symlink_metadata`, not `metadata`: `fs::metadata` *follows* reparse points,
    // so the `FILE_ATTRIBUTE_REPARSE_POINT` test below could only ever observe the
    // target's attributes. A link planted inside the install directory pointing at
    // any PE on the machine satisfied "regular file, not a reparse point".
    let meta = fs::symlink_metadata(path).map_err(|e| format!("{label}: {e}"))?;
    if !meta.is_file() {
        return Err(format!("{label} is not a regular file").into());
    }
    if meta.len() == 0 {
        return Err(format!("{label} is empty").into());
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        if meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(format!("{label} must not be a reparse point/symlink").into());
        }
        // PE header check (MZ) — fail closed if unreadable or not PE.
        let mut hdr = [0u8; 2];
        let mut f = fs::File::open(path).map_err(|e| format!("{label}: cannot open: {e}"))?;
        use std::io::Read;
        f.read_exact(&mut hdr)
            .map_err(|e| format!("{label}: cannot read PE header: {e}"))?;
        if hdr != *b"MZ" {
            return Err(format!("{label} is not a Windows PE binary").into());
        }
    }
    let app_root = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()));
    // The root test runs on the *canonical* path or not at all. Falling back to the
    // raw path on a failed canonicalize meant `…\Aether\..\..\evil\aether.exe` was
    // compared as a string against `…\Aether` and passed — a `..` walk out of the
    // trusted root, straight into the elevated TUN launch.
    let canon = path.canonicalize().map_err(|e| {
        CommandError::new(
            "validation",
            format!(
                "{label} rejected: its final path cannot be resolved ({e}), so it cannot be \
                 shown to live under a trusted root"
            ),
        )
    })?;
    let roots = allowed_binary_roots(app_root.as_deref());
    for root in &roots {
        if canon.starts_with(root) {
            return Ok(());
        }
    }
    Err(format!(
        "{label} rejected: must live under the app install directory (got {})",
        canon.display()
    )
    .into())
}

/// The only directories an engine binary may live in.
///
/// This used to be "the exe's directory and its parent", which for an installed
/// app is `C:\Program Files` — a root that includes every other vendor's folder —
/// and for the portable package is whatever directory the user extracted the zip
/// into, i.e. usually somewhere writable. The child launched from there is handed
/// the DPAPI master key, so "under the install directory, broadly" was not a
/// boundary worth the name. Named layout directories only, plus the repository
/// build path the dev fallback resolves, which is a fixed constant rather than a
/// place an attacker gets to write by being lucky.
pub fn allowed_binary_roots(exe_dir: Option<&Path>) -> Vec<PathBuf> {
    let mut roots: Vec<PathBuf> = Vec::new();
    if let Some(dir) = exe_dir {
        for candidate in [dir.to_path_buf(), dir.join("resources"), dir.join("engine")] {
            roots.push(candidate.canonicalize().unwrap_or(candidate));
        }
    }
    // `cargo run` / `cargo test` from the repository: the engine sits in the
    // workspace's release target directory, which is no relation to where the
    // shell binary happens to be.
    let repo_build = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../aether/target/release")
        .join(if cfg!(windows) {
            "aether.exe"
        } else {
            "aether"
        });
    roots.push(repo_build.canonicalize().unwrap_or(repo_build));
    roots
}

pub fn file_sha256_hex(path: &Path) -> Result<String, CommandError> {
    use sha2::{Digest, Sha256};
    use std::io::Read;
    let mut file =
        fs::File::open(path).map_err(|e| format!("cannot open {}: {e}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = file
            .read(&mut buf)
            .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let res = hasher.finalize();
    let mut s = String::with_capacity(64);
    for b in res {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
    }
    Ok(s)
}

include!(concat!(env!("OUT_DIR"), "/release_hashes.rs"));

/// Which witness this binary was built against, for logs and for support output:
/// the anchor's verbatim bytes, its own digest, the table derived from it, and
/// whether any entry is still the un-published placeholder.
pub fn engine_trust_anchor() -> (
    &'static [u8],
    &'static str,
    &'static [(&'static str, &'static str)],
    bool,
) {
    (
        ENGINE_TRUST_ANCHOR_BYTES,
        ENGINE_TRUST_ANCHOR_SHA256,
        EMBEDDED_RELEASE_HASHES,
        ENGINE_TRUST_ANCHOR_HAS_PLACEHOLDER,
    )
}

/// The all-zero digest `engine-trust.json` carries for an artifact whose witness
/// the release job has not published yet. It is unsatisfiable by construction, so
/// treating it as an ordinary mismatch would report a real file as tampered with.
const PLACEHOLDER_SHA256: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, Clone)]
pub struct TrustedBinaryPolicy {
    /// Compiles *only* into a debug build.
    ///
    /// This used to be a plain `allow_unsigned_in_debug: bool` that
    /// `for_engine()` set to `true`, so the decision to skip Authenticode for
    /// the binary that receives the DPAPI master key lived in runtime data on
    /// every build, and only the extra `cfg!(debug_assertions)` at the use site
    /// kept a release build honest. There is now no field, and no code path, in
    /// a release binary that can decline a signature check.
    #[cfg(debug_assertions)]
    pub allow_unsigned_for_dev: bool,
    pub expected_publisher_cn: &'static str,
    pub embedded_hashes: &'static [(&'static str, &'static str)],
    pub enforce_hash_match: bool,
}

impl Default for TrustedBinaryPolicy {
    fn default() -> Self {
        Self::for_engine()
    }
}

impl TrustedBinaryPolicy {
    pub fn for_engine() -> Self {
        Self {
            #[cfg(debug_assertions)]
            allow_unsigned_for_dev: true,
            expected_publisher_cn: "deathline94",
            embedded_hashes: EMBEDDED_RELEASE_HASHES,
            enforce_hash_match: !cfg!(debug_assertions),
        }
    }

    pub fn for_wintun() -> Self {
        Self {
            #[cfg(debug_assertions)]
            allow_unsigned_for_dev: false,
            expected_publisher_cn: "WireGuard LLC",
            embedded_hashes: EMBEDDED_RELEASE_HASHES,
            enforce_hash_match: !cfg!(debug_assertions),
        }
    }
}

#[derive(Debug)]
pub enum BinaryTrustError {
    Validation(String),
    Authenticode(i32, String),
    PublisherMismatch {
        expected: String,
        found: String,
    },
    HashMismatch {
        filename: String,
        expected: String,
        actual: String,
    },
    MissingHash {
        filename: String,
    },
    AnchorNotPublished {
        filename: String,
    },
}

impl std::fmt::Display for BinaryTrustError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Validation(s) => write!(f, "Binary validation failed: {s}"),
            Self::Authenticode(code, msg) => {
                write!(f, "Authenticode verification failed (0x{code:08x}): {msg}")
            }
            Self::PublisherMismatch { expected, found } => {
                write!(
                    f,
                    "Publisher mismatch: expected '{expected}', found '{found}'"
                )
            }
            Self::HashMismatch {
                filename,
                expected,
                actual,
            } => {
                write!(
                    f,
                    "Hash mismatch for {filename}: expected {expected}, actual {actual}"
                )
            }
            Self::MissingHash { filename } => {
                write!(f, "Missing release hash in embedded policy for {filename}")
            }
            Self::AnchorNotPublished { filename } => write!(
                f,
                "No trust anchor published for {filename}: packaging/trust/engine-trust.json \
                 still carries its placeholder digest for this artifact, so nothing can be \
                 compared against. Record the signed build's sha256 there (see that file's \
                 $comment and packaging/trust/README.md); this is a release-pipeline gap, not a \
                 damaged install."
            ),
        }
    }
}

impl std::error::Error for BinaryTrustError {}

/// The pinned signing-certificate digest the anchor holds for `filename`, or
/// `None` when the anchor carries no entry or only the all-zero placeholder.
pub fn embedded_cert_pin(filename: &str) -> Option<&'static str> {
    EMBEDDED_ISSUER_CERTS
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(filename))
        .map(|(_, digest)| *digest)
        .filter(|digest| *digest != PLACEHOLDER_SHA256)
}

/// Does this X.500 subject name `expected_cn` as a whole CN RDN value?
///
/// `subject.contains("CN=deathline94")` matched `CN=deathline94.example.com`, and
/// the looser `eq_ignore_ascii_case` fallback matched a subject with no `CN=` at
/// all — so any certificate whose common name merely *starts* with the expected
/// text passed "published by deathline94". Distinguished names are compared per
/// RDN instead: `CN=deathline94` matches, `CN=deathline94.example.com` and
/// `O=CN=deathline94` do not.
pub fn subject_names_common_name(subject: &str, expected_cn: &str) -> bool {
    let expected = expected_cn.trim();
    if expected.is_empty() {
        return false;
    }
    let bytes = subject.as_bytes();
    let mut start = 0usize;
    let mut quoted = false;
    let mut escaped = false;
    let mut matched = false;
    for (index, byte) in bytes.iter().enumerate() {
        if escaped {
            escaped = false;
            continue;
        }
        match byte {
            b'\\' => escaped = true,
            b'"' => quoted = !quoted,
            b',' | b';' if !quoted => {
                matched |= cn_rdn_matches(&subject[start..index], expected);
                start = index + 1;
            }
            _ => {}
        }
    }
    matched || cn_rdn_matches(&subject[start..], expected)
}

fn cn_rdn_matches(rdn: &str, expected: &str) -> bool {
    let Some((name, value)) = rdn.split_once('=') else {
        return false;
    };
    if !name.trim().eq_ignore_ascii_case("CN") {
        return false;
    }
    let value = value.trim();
    let value = value
        .strip_prefix('"')
        .and_then(|v| v.strip_suffix('"'))
        .unwrap_or(value);
    // Undo the `\,` / `\"` escaping a DN uses inside quoted values.
    let mut unescaped = String::with_capacity(value.len());
    let mut chars = value.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => match chars.next() {
                Some(next) => unescaped.push(next),
                None => unescaped.push(c),
            },
            other => unescaped.push(other),
        }
    }
    unescaped.trim().eq_ignore_ascii_case(expected)
}

#[cfg(windows)]
pub fn verify_authenticode_signature(
    path: &Path,
    expected_cn: &str,
    expected_cert_sha256: Option<&str>,
) -> Result<(), BinaryTrustError> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Security::WinTrust::{
        WinVerifyTrust, WINTRUST_DATA, WINTRUST_FILE_INFO, WTD_CACHE_ONLY_URL_RETRIEVAL,
        WTD_CHOICE_FILE, WTD_DISABLE_MD2_MD4, WTD_REVOCATION_CHECK_NONE, WTD_REVOKE_NONE,
        WTD_STATEACTION_IGNORE, WTD_UI_NONE,
    };

    let wide_path: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let mut file_info = WINTRUST_FILE_INFO {
        cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: wide_path.as_ptr(),
        hFile: 0 as _,
        pgKnownSubject: std::ptr::null_mut(),
    };

    const WINTRUST_ACTION_GENERIC_VERIFY_V2: windows_sys::core::GUID = windows_sys::core::GUID {
        data1: 0x00aac56b,
        data2: 0xcd44,
        data3: 0x11d0,
        data4: [0x8c, 0xeb, 0x00, 0xc0, 0x4f, 0xc2, 0xaa, 0xe5],
    };

    let mut trust_data = WINTRUST_DATA {
        cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
        pPolicyCallbackData: std::ptr::null_mut(),
        pSIPClientData: std::ptr::null_mut(),
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_NONE,
        dwUnionChoice: WTD_CHOICE_FILE,
        Anonymous: windows_sys::Win32::Security::WinTrust::WINTRUST_DATA_0 {
            pFile: &mut file_info,
        },
        // IGNORE, not CLOSE: `WTD_STATEACTION_CLOSE` only releases the cached
        // state, and releasing requires a *second* WinVerifyTrust call with the
        // same hWVTStateData — a single CLOSE call would leak it.
        dwStateAction: WTD_STATEACTION_IGNORE,
        hWVTStateData: 0 as _,
        pwszURLReference: std::ptr::null_mut(),
        // 0x80 is WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT, not ..._NONE, so the
        // value written here asked for a whole-chain CRL/OCSP walk on every
        // launch — which fails closed on an offline machine and, in CI, against
        // a just-issued certificate whose CRL is not published yet. Ask for no
        // revocation walk, but do refuse the broken legacy digests.
        dwProvFlags: WTD_REVOCATION_CHECK_NONE | WTD_DISABLE_MD2_MD4 | WTD_CACHE_ONLY_URL_RETRIEVAL,
        dwUIContext: 0,
        pSignatureSettings: std::ptr::null_mut(),
    };

    let mut action_id = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    let status = unsafe {
        WinVerifyTrust(
            0 as _,
            &mut action_id,
            &mut trust_data as *mut _ as *mut std::ffi::c_void,
        )
    };

    if status != 0 {
        return Err(BinaryTrustError::Authenticode(
            status,
            format!("WinVerifyTrust returned error code: 0x{status:08x}"),
        ));
    }

    if !expected_cn.is_empty() || expected_cert_sha256.is_some() {
        // Full path: `powershell.exe` resolved through the search order that puts
        // the application directory first.
        let shell = crate::acl::system32("WindowsPowerShell\\v1.0\\powershell.exe")
            .map_err(|e| BinaryTrustError::Validation(e.message))?;
        let quoted = path.to_string_lossy().replace('\'', "''");
        // The leaf's own digest, sha256 over its DER — which is what the anchor's
        // `cert_sha256` field is defined as, and *not* the SHA-1 store thumbprint
        // `Get-AuthenticodeSignature` exposes as `Thumbprint`.
        let ps_cmd = format!(
            "$c = (Get-AuthenticodeSignature -LiteralPath '{quoted}').SignerCertificate; \
             if ($null -eq $c) {{ exit 3 }}; \
             $sha = [System.BitConverter]::ToString( \
             [System.Security.Cryptography.SHA256]::Create().ComputeHash($c.RawData) \
             ) -replace '-',''; Write-Output $sha; Write-Output $c.Subject"
        );
        let out = Command::new(&shell)
            .args(["-NoProfile", "-NonInteractive", "-Command", &ps_cmd])
            .output()
            .map_err(|e| {
                BinaryTrustError::Validation(format!("failed to query signer certificate: {e}"))
            })?;

        if !out.status.success() {
            return Err(BinaryTrustError::Validation(format!(
                "failed to read signer certificate: {}",
                String::from_utf8_lossy(&out.stderr)
            )));
        }

        let text = String::from_utf8_lossy(&out.stdout).replace("\r\n", "\n");
        let mut lines = text.trim().splitn(2, '\n');
        let found_hash = lines.next().unwrap_or("").trim().to_ascii_lowercase();
        let subject = lines.next().unwrap_or("").trim().to_string();

        // The certificate itself, not what it says it is called. A subject the
        // signer writes is free; the leaf digest is only obtainable from whoever
        // holds the private key that the release job recorded.
        if let Some(pinned) = expected_cert_sha256 {
            if found_hash != pinned.to_ascii_lowercase() {
                return Err(BinaryTrustError::PublisherMismatch {
                    expected: format!("{expected_cn} (leaf sha256 {pinned})"),
                    found: format!("{subject} (leaf sha256 {found_hash})"),
                });
            }
        }
        if !expected_cn.is_empty() && !subject_names_common_name(&subject, expected_cn) {
            return Err(BinaryTrustError::PublisherMismatch {
                expected: expected_cn.to_string(),
                found: subject,
            });
        }
    }

    Ok(())
}

#[cfg(not(windows))]
pub fn verify_authenticode_signature(
    _path: &Path,
    _expected_cn: &str,
    _expected_cert_sha256: Option<&str>,
) -> Result<(), BinaryTrustError> {
    Ok(())
}

pub fn verify_elevated_binary(
    path: &Path,
    label: &str,
    policy: &TrustedBinaryPolicy,
) -> Result<(), BinaryTrustError> {
    // Which witness the running binary holds has to be recoverable from the logs
    // alone, otherwise a refusal is indistinguishable from an old build.
    static ANCHOR_LOGGED: std::sync::Once = std::sync::Once::new();
    let (_, anchor_sha, table, has_placeholder) = engine_trust_anchor();
    ANCHOR_LOGGED.call_once(|| {
        eprintln!(
            "[trust] engine-trust.json sha256={anchor_sha} entries={} placeholder_digest_present={has_placeholder}",
            table.len()
        );
    });

    let path_buf = path.to_path_buf();
    validate_trusted_binary(&path_buf, label)
        .map_err(|e| BinaryTrustError::Validation(e.message))?;
    // Hash and authenticate the *final* path. The two checks used to open whatever
    // name the caller passed while the root test resolved it separately, so the
    // bytes witnessed here and the file later launched were not guaranteed to be
    // the same object.
    let verified_path = path.canonicalize().map_err(|e| {
        BinaryTrustError::Validation(format!(
            "{}: cannot resolve a final path for verification ({e})",
            path.display()
        ))
    })?;

    let filename = path.file_name().and_then(|n| n.to_str()).unwrap_or(label);

    let actual_hash =
        file_sha256_hex(&verified_path).map_err(|e| BinaryTrustError::Validation(e.message))?;

    let mut found_hash = false;
    for &(expected_name, expected_hash) in policy.embedded_hashes {
        if expected_name.eq_ignore_ascii_case(filename) || expected_name.eq_ignore_ascii_case(label)
        {
            found_hash = true;
            if actual_hash.eq_ignore_ascii_case(expected_hash) {
                continue;
            }
            if expected_hash == PLACEHOLDER_SHA256 {
                // Nothing has been witnessed for this artifact yet, so this is a
                // pipeline gap rather than tampering. A debug build asserts
                // nothing about release provenance and may proceed; a release
                // build refuses, because "no comparison possible" is not a pass.
                if policy.enforce_hash_match {
                    return Err(BinaryTrustError::AnchorNotPublished {
                        filename: filename.to_string(),
                    });
                }
                continue;
            }
            return Err(BinaryTrustError::HashMismatch {
                filename: filename.to_string(),
                expected: expected_hash.to_string(),
                actual: actual_hash,
            });
        }
    }

    if policy.enforce_hash_match && !found_hash {
        return Err(BinaryTrustError::MissingHash {
            filename: filename.to_string(),
        });
    }

    #[cfg(windows)]
    {
        // sha256 of the signing leaf, straight from the same anchor the file
        // digests come from. Absent (or the all-zero placeholder) means nothing is
        // pinned, which a release build may not treat as a pass for the same
        // reason it does not treat an absent file digest as one.
        let pinned = embedded_cert_pin(filename).or_else(|| embedded_cert_pin(label));
        if pinned.is_none() && policy.enforce_hash_match {
            return Err(BinaryTrustError::AnchorNotPublished {
                filename: filename.to_string(),
            });
        }
        let auth_res =
            verify_authenticode_signature(&verified_path, policy.expected_publisher_cn, pinned);
        match auth_res {
            Ok(()) => {}
            Err(e) => {
                // Exactly one outcome exists in a release binary: refuse.
                #[cfg(debug_assertions)]
                if policy.allow_unsigned_for_dev {
                    eprintln!("[warn] debug build only, Authenticode check skipped: {e}");
                    return Ok(());
                }
                #[cfg(not(debug_assertions))]
                let _ = &e;
                return Err(e);
            }
        }
    }

    Ok(())
}

/// Verify the engine binary this process is about to spawn, in **every** mode.
///
/// The call used to live inside `if settings.routing_mode == RoutingMode::Tun`, so the
/// unelevated proxy/socks paths started a binary whose signature and digest
/// nobody had looked at: `engine_path` only proves "a PE under an allowed root",
/// which a dropped-in file satisfies. Wrapping it in one named function keeps a
/// mode from being able to opt out again by accident, and gives the invariant
/// gate a single token to count against the spawn sites.
pub(crate) fn verify_engine_or_refuse(path: &Path) -> Result<(), CommandError> {
    verify_elevated_binary(path, "aether.exe", &TrustedBinaryPolicy::for_engine())
        .map_err(CommandError::from)
}
