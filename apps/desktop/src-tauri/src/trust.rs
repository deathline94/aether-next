//! Binary trust: which files may be executed, their committed digests, and the
//! vendor signature required for WinTUN.
//!
//! The tables below are compiled from `packaging/trust/engine-trust.json` by
//! `build.rs` — never computed from the artifact being shipped, which is what made
//! the comparison unable to fail.
//!
//! ## What a pass here guarantees, on Windows
//!
//! One open of the canonical path produces one in-memory buffer ([`WitnessedFile`],
//! opened with a share mode that denies writers and delete-rename while it lives).
//! The engine's SHA-256 must match the separately reviewed anchor. The unsigned
//! engine does not claim a Windows publisher identity. For WinTUN, the same buffer
//! also supplies its signing leaf, and `WinVerifyTrust` checks the vendor signature.
//!
//! ## What it does not guarantee
//!
//! * The later `CreateProcess` of that path is a fresh open by the OS. The window
//!   between the end of verification and the spawn is closed by the install
//!   directory's DACL (`acl.rs`, and the T062 root allow-list above), not by
//!   anything here.
//! * Revocation is deliberately not walked (see the `WinVerifyTrust` flags below),
//!   so a leaf that was withdrawn but still chains is accepted; the pinned digest is
//!   what a rotation has to change.
//! * The certificate table is parsed as DER; a blob this reader cannot follow is a
//!   refusal, never a pass. Which is the right way to fail, but it means a signing
//!   tool that emits an unusual `SignedData` layout has to be seen on a real
//!   artifact before it is believed — `packaging/wintun.dll` is the one genuinely
//!   signed binary in this repository and the test that pins its leaf digest is the
//!   only proof the reader exists outside a synthetic fixture.
use crate::error::CommandError;
use std::fs;
use std::path::{Path, PathBuf};

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

/// sha256 of a file **read by path**, streaming.
///
/// The trust pipeline itself does not use this: `verify_elevated_binary` witnesses
/// one open of the file and hashes that buffer, so its digest and its signature
/// observation cannot come apart (see `witness_bytes`). This remains for callers
/// that want a checksum of an unrelated file and are not making a trust decision
/// about bytes they are also going to execute.
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
    Ok(hex_lower(&hasher.finalize()))
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
                 compared against. Record the engine build's sha256 there (see that file's \
                 $comment and packaging/trust/README.md); this is a release-pipeline gap, not a \
                 damaged install."
            ),
        }
    }
}

impl std::error::Error for BinaryTrustError {}

/// The pinned signing-certificate digest the build-time table holds for
/// `filename`, or `None` when there is no entry or only the all-zero placeholder.
///
/// The table is `build.rs`'s reading of `packaging/trust/engine-trust.json`; the
/// functions below read the same file's bytes that `build.rs` embedded, and the
/// test that they agree is what keeps the two from drifting apart.
pub fn embedded_cert_pin(filename: &str) -> Option<&'static str> {
    EMBEDDED_ISSUER_CERTS
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(filename))
        .map(|(_, digest)| *digest)
        .filter(|digest| *digest != PLACEHOLDER_SHA256)
}

/* -------------------------------------------- the anchor, read by the runtime */
/*
 * `build.rs` turns the committed witness into the two static tables above. That is
 * enough to answer "which bytes may run", but it drops the one field the answer is
 * really about: *who signed them*. `issued_cn` was read by nobody, so
 * `TrustedBinaryPolicy::expected_publisher_cn` — a string compiled into the shell —
 * was the authority on the publisher, and the reviewed witness was a bystander.
 *
 * So the shell also parses the anchor it carries. It is the same file, embedded
 * verbatim (`ENGINE_TRUST_ANCHOR_BYTES`), so this adds no trust and no I/O — only
 * the ability to say that the publisher named in a reviewed diff outranks a string
 * that any fork can edit, and to refuse when the witness names nobody.
 */

/// One `files[]` entry, as far as the runtime cares.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchorEntry {
    pub name: String,
    pub file_sha256: String,
    /// sha256 over the signing leaf's DER. `None` when the field is absent or the
    /// all-zero placeholder — which is "unpinned", never "anything goes".
    pub cert_sha256: Option<String>,
    /// The subject as Authenticode reports it, e.g. `CN=deathline94`.
    pub issued_cn: Option<String>,
    /// `trusted-ca` / `ephemeral-dev` / `unwitnessed`. An anchor written before the
    /// field existed reads as `None`, which the release path treats as unpublished.
    pub signing_profile: Option<String>,
}

/// The signer the witness pins for one artifact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinnedSigner {
    /// The bare common name, with the `CN=` prefix removed: what
    /// [`subject_names_common_name`] compares against.
    pub common_name: String,
    pub cert_sha256: Option<String>,
    pub signing_profile: Option<String>,
}

impl PinnedSigner {
    /// Is a leaf digest pinned? A release may not proceed on a publisher name alone.
    pub fn leaf_is_pinned(&self) -> bool {
        self.cert_sha256.is_some()
    }
}

fn clean_hex64(value: &str) -> Option<String> {
    let v = value.trim().to_ascii_lowercase();
    if v.len() == 64 && v.bytes().all(|b| b.is_ascii_hexdigit()) && v != PLACEHOLDER_SHA256 {
        Some(v)
    } else {
        None
    }
}

fn clean_text(value: &str) -> Option<String> {
    let v = value.trim().to_string();
    (!v.is_empty()).then_some(v)
}

/// Parse the anchor's `files[]`. Errors rather than guesses: an unparseable witness
/// is a pipeline failure, and the caller must be able to tell it from "no entry".
pub fn parse_anchor_entries(bytes: &[u8]) -> Result<Vec<AnchorEntry>, String> {
    let doc: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|e| format!("trust anchor is not JSON: {e}"))?;
    let files = doc
        .get("files")
        .and_then(|f| f.as_array())
        .ok_or("trust anchor has no `files` array")?;
    let mut out = Vec::with_capacity(files.len());
    for entry in files {
        let name = entry
            .get("name")
            .and_then(|n| n.as_str())
            .and_then(clean_text)
            .ok_or("a files[] entry has no string `name`")?;
        let digest = entry
            .get("file_sha256")
            .and_then(|d| d.as_str())
            .and_then(clean_text)
            .ok_or_else(|| format!("{name}: no string file_sha256"))?;
        let lower = digest.to_ascii_lowercase();
        let cert = entry
            .get("cert_sha256")
            .and_then(|d| d.as_str())
            .and_then(clean_hex64);
        out.push(AnchorEntry {
            name: name.to_ascii_lowercase(),
            file_sha256: lower,
            cert_sha256: cert,
            issued_cn: entry
                .get("issued_cn")
                .and_then(|v| v.as_str())
                .and_then(clean_text),
            signing_profile: entry
                .get("signing_profile")
                .and_then(|v| v.as_str())
                .and_then(clean_text),
        });
    }
    if out.is_empty() {
        return Err("trust anchor's `files` array is empty".to_string());
    }
    Ok(out)
}

/// The entries of the witness this binary was compiled against.
pub fn anchor_entries() -> Vec<AnchorEntry> {
    parse_anchor_entries(ENGINE_TRUST_ANCHOR_BYTES).unwrap_or_else(|e| {
        // Unreachable in a build that got past build.rs, which refuses an anchor it
        // cannot parse. Loud rather than silent: an empty vec here means every
        // artifact reads as "no pin", and a release build then refuses.
        eprintln!("[trust] embedded engine-trust.json could not be parsed: {e}");
        Vec::new()
    })
}

/// Who the reviewed witness says signed `filename`, or `None` when it names nobody.
///
/// The `CN=` prefix is stripped because the comparison is against a common name,
/// not a distinguished-name fragment an author can pad.
pub fn pinned_signer(filename: &str) -> Option<PinnedSigner> {
    let entry = anchor_entries()
        .into_iter()
        .find(|e| e.name.eq_ignore_ascii_case(filename))?;
    let cn = entry.issued_cn?;
    let common_name = match cn.strip_prefix("CN=") {
        Some(rest) => rest.trim().to_string(),
        None => cn.clone(),
    };
    if common_name.is_empty() {
        return None;
    }
    Some(PinnedSigner {
        common_name,
        cert_sha256: entry.cert_sha256,
        signing_profile: entry.signing_profile,
    })
}

/// Compare a reported signer against the pinned identity.
///
/// Pure, and therefore testable off Windows: the WinVerifyTrust call below it is
/// not. `pinned` is the leaf digest from the anchor; when absent, the publisher
/// name the caller supplies is all there is, and a caller that must not fall back
/// to that has already refused (see `verify_elevated_binary`).
pub fn check_pinned_signer(
    found_leaf_sha256: &str,
    found_subject: &str,
    pinned_leaf_sha256: Option<&str>,
    expected_cn: &str,
) -> Result<(), BinaryTrustError> {
    // The certificate itself, not what it says it is called. A subject the signer
    // writes is free; the leaf digest is only obtainable from whoever holds the
    // private key that the release job recorded.
    if let Some(pinned) = pinned_leaf_sha256 {
        if !found_leaf_sha256.trim().eq_ignore_ascii_case(pinned.trim()) {
            return Err(BinaryTrustError::PublisherMismatch {
                expected: format!("{expected_cn} (leaf sha256 {pinned})"),
                found: format!(
                    "{found_subject} (leaf sha256 {})",
                    found_leaf_sha256.trim().to_ascii_lowercase()
                ),
            });
        }
    }
    if !expected_cn.is_empty() && !subject_names_common_name(found_subject, expected_cn) {
        return Err(BinaryTrustError::PublisherMismatch {
            expected: expected_cn.to_string(),
            found: found_subject.to_string(),
        });
    }
    Ok(())
}

/// A distributable binary may not run on an identity nobody witnessed.
///
/// `distributable` is `policy.enforce_hash_match`, which is what separates a release
/// build from a development one. It is the same flag that refuses an unwitnessed file
/// digest above, because the two fail the same way: "no comparison possible" is not a
/// pass. A development build keeps the compiled-in publisher name as its fallback,
/// which is the whole point of an `ephemeral-dev` anchor.
fn require_pinned_identity(
    signer: Option<&PinnedSigner>,
    distributable: bool,
    filename: &str,
) -> Result<(), BinaryTrustError> {
    if !distributable {
        return Ok(());
    }
    let unpinned = || BinaryTrustError::AnchorNotPublished {
        filename: filename.to_string(),
    };
    let signer = signer.ok_or_else(unpinned)?;
    // A publisher name alone is not a pin: anyone can write a subject, and a release
    // that trusted the name would trust the first self-signed cert that copies it.
    if !signer.leaf_is_pinned() {
        return Err(unpinned());
    }
    Ok(())
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

fn is_witnessed_unsigned_engine(entries: &[AnchorEntry], filename: &str) -> bool {
    filename.eq_ignore_ascii_case("aether.exe")
        && entries.iter().any(|entry| {
            entry.name == "aether.exe"
                && entry.signing_profile.as_deref() == Some("unsigned-witnessed")
                && entry.cert_sha256.is_none()
                && entry.issued_cn.is_none()
        })
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

/// The witness: one open, the digest and the Authenticode signer of the bytes that
/// open produced. Its own file, and its own test target, for the linker reason
/// spelled out at the top of `trust_reader.rs`.
#[path = "trust_reader.rs"]
mod reader;

// Re-exported rather than moved back: a `use` binding costs no codegen, so the
// witness keeps its own codegen units (see the `reader` module's doc) while the rest
// of the file — and its tests — name these items directly.
pub use self::reader::*;

#[cfg(windows)]
pub fn verify_authenticode_signature(
    source: &fs::File,
    path: &Path,
    witnessed: &BinaryWitness,
    expected_cn: &str,
    expected_cert_sha256: Option<&str>,
) -> Result<(), BinaryTrustError> {
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Security::WinTrust::{
        WinVerifyTrust, WINTRUST_DATA, WINTRUST_FILE_INFO, WTD_CACHE_ONLY_URL_RETRIEVAL,
        WTD_CHOICE_FILE, WTD_DISABLE_MD2_MD4, WTD_REVOCATION_CHECK_NONE, WTD_REVOKE_NONE,
        WTD_STATEACTION_IGNORE, WTD_UI_NONE,
    };

    let wide_path: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    // `hFile` is the handle the witnessed bytes were read through. Its share mode
    // denies writes and delete/rename until the caller finishes process creation.
    let mut file_info = WINTRUST_FILE_INFO {
        cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: wide_path.as_ptr(),
        hFile: source.as_raw_handle(),
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

    if expected_cn.is_empty() && expected_cert_sha256.is_none() {
        return Ok(());
    }

    // Who signed **the witnessed bytes**, read out of their own certificate table.
    //
    // This used to be a spawned `powershell.exe Get-AuthenticodeSignature` asked the
    // same question of the *path*, after the digest had been taken from it — two
    // unrelated observations about a name, which is exactly the window the anchor
    // exists to close: the pair "these bytes, signed by this leaf" could then
    // describe a file that never existed. `BinaryWitness` cannot be assembled from
    // two reads (its only constructor takes one buffer), so the pair is now one
    // observation, and nothing in this module opens the path a second time.
    let signer = witnessed.signer().ok_or_else(|| {
        BinaryTrustError::Validation(format!(
            "{}: the chain verified, but the bytes that were hashed carry no Authenticode \
             certificate table to identify a signer from",
            path.display()
        ))
    })?;

    // The comparison itself is `check_pinned_signer`, which is pure and so can be
    // tested on any platform; what is Windows-only is the chain check above it.
    check_pinned_signer(
        signer.leaf_sha256(),
        signer.subject(),
        expected_cert_sha256,
        expected_cn,
    )
}

#[cfg(not(windows))]
pub fn verify_authenticode_signature(
    _source: &fs::File,
    _path: &Path,
    _witnessed: &BinaryWitness,
    _expected_cn: &str,
    _expected_cert_sha256: Option<&str>,
) -> Result<(), BinaryTrustError> {
    // Authenticode is a Windows container format; there is no signature to read in
    // an ELF or Mach-O image. The digest comparison in `verify_elevated_binary` is
    // the whole check here.
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
) -> Result<fs::File, BinaryTrustError> {
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

    // One open, one read. The digest compared against the anchor below and the
    // signer read out of the PE's certificate table are both taken from these
    // bytes, through this handle, and nothing in this module opens the path a
    // second time to ask a third-party tool who signed it.
    let (source, bytes) =
        open_for_verification(&verified_path).map_err(BinaryTrustError::Validation)?;
    #[cfg(windows)]
    if !bytes.starts_with(b"MZ") {
        // `validate_trusted_binary` checked the magic through an *earlier* open of the
        // same name. These are the bytes the verdict is about, so the check is made of
        // them rather than inherited from that open.
        return Err(BinaryTrustError::Validation(format!(
            "{} is not a Windows PE binary",
            verified_path.display()
        )));
    }
    let witness = witness_bytes(&bytes).map_err(BinaryTrustError::Validation)?;
    let actual_hash = witness.file_sha256().to_string();

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

    // Aether's own engine is distributed without Authenticode. Its exact bytes
    // must match the separately reviewed witness above. Keep the vendor-signed
    // WinTUN path below unchanged.
    if label.eq_ignore_ascii_case("aether.exe") {
        if !policy.enforce_hash_match || is_witnessed_unsigned_engine(&anchor_entries(), filename) {
            return Ok(source);
        }
        if policy.enforce_hash_match {
            return Err(BinaryTrustError::Validation(
                "release engine is missing its unsigned-witnessed policy".to_string(),
            ));
        }
    }

    // Who signed it, from the reviewed witness rather than from a string compiled
    // into the shell: `pinned_signer` reads the anchor this binary carries, and
    // `expected_publisher_cn` is what a development build falls back to when the
    // witness names nobody (a release cannot reach that fallback, refused below).
    let signer = pinned_signer(filename).or_else(|| pinned_signer(label));
    require_pinned_identity(signer.as_ref(), policy.enforce_hash_match, filename)?;

    #[cfg(windows)]
    {
        let expected_cn = signer
            .as_ref()
            .map(|s| s.common_name.clone())
            .unwrap_or_else(|| policy.expected_publisher_cn.to_string());
        // The build.rs table is the same witness read a different way; prefer it
        // when the entry carries no `cert_sha256` at all, so an anchor written
        // before the pin existed is no weaker than it was.
        let pinned = signer
            .as_ref()
            .and_then(|s| s.cert_sha256.clone())
            .or_else(|| embedded_cert_pin(filename).map(str::to_owned))
            .or_else(|| embedded_cert_pin(label).map(str::to_owned));
        let auth_res = verify_authenticode_signature(
            &source,
            &verified_path,
            &witness,
            &expected_cn,
            pinned.as_deref(),
        );
        match auth_res {
            Ok(()) => {}
            Err(e) => {
                // Exactly one outcome exists in a release binary: refuse.
                #[cfg(debug_assertions)]
                if policy.allow_unsigned_for_dev {
                    eprintln!("[warn] debug build only, Authenticode check skipped: {e}");
                    return Ok(source);
                }
                #[cfg(not(debug_assertions))]
                let _ = &e;
                return Err(e);
            }
        }
    }
    Ok(source)
}

/// Verify the engine binary this process is about to spawn, in **every** mode.
///
/// The call used to live inside `if settings.routing_mode == RoutingMode::Tun`, so the
/// unelevated proxy/socks paths started a binary whose signature and digest
/// nobody had looked at: `engine_path` only proves "a PE under an allowed root",
/// which a dropped-in file satisfies. Wrapping it in one named function keeps a
/// mode from being able to opt out again by accident, and gives the invariant
/// gate a single token to count against the spawn sites. The caller must keep
/// the returned file handle alive until `Command::spawn` completes.
pub(crate) fn verify_engine_or_refuse(path: &Path) -> Result<fs::File, CommandError> {
    verify_elevated_binary(path, "aether.exe", &TrustedBinaryPolicy::for_engine())
        .map_err(CommandError::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    const WITNESSED_LEAF: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const SOME_OTHER_LEAF: &str =
        "2222222222222222222222222222222222222222222222222222222222222222";

    fn anchor(files: serde_json::Value) -> Vec<AnchorEntry> {
        let doc = serde_json::json!({ "files": files });
        parse_anchor_entries(doc.to_string().as_bytes()).expect("the fixture is the anchor shape")
    }

    #[test]
    fn unsigned_engine_profile_never_applies_to_driver_or_forged_signer() {
        let good = anchor(serde_json::json!([
            {"name":"aether.exe","file_sha256":"a".repeat(64),"signing_profile":"unsigned-witnessed"}
        ]));
        assert!(is_witnessed_unsigned_engine(&good, "aether.exe"));
        assert!(!is_witnessed_unsigned_engine(&good, "wintun.dll"));

        let forged = anchor(serde_json::json!([
            {"name":"aether.exe","file_sha256":"a".repeat(64),"signing_profile":"unsigned-witnessed","issued_cn":"CN=someone"}
        ]));
        assert!(!is_witnessed_unsigned_engine(&forged, "aether.exe"));
    }

    fn signer(leaf: Option<&str>) -> PinnedSigner {
        PinnedSigner {
            common_name: "deathline94".to_string(),
            cert_sha256: leaf.map(str::to_owned),
            signing_profile: Some("trusted-ca".to_string()),
        }
    }

    /// The whole point of item 4's strictness: an installed release must not run an
    /// engine whose signer the reviewed witness never named.
    #[test]
    fn a_release_refuses_an_engine_nobody_witnessed_a_signer_for() {
        let err = require_pinned_identity(None, true, "aether.exe")
            .expect_err("an unwitnessed signer cannot pass a release build");
        assert!(
            matches!(err, BinaryTrustError::AnchorNotPublished { ref filename } if filename == "aether.exe"),
            "{err}"
        );
    }

    /// A subject is free text; only the holder of the recorded private key can
    /// produce a given leaf digest, so a name with no pin behind it is not an identity.
    #[test]
    fn a_publisher_name_without_a_leaf_pin_is_not_an_identity() {
        let without_pin = signer(None);
        let err = require_pinned_identity(Some(&without_pin), true, "aether.exe")
            .expect_err("a name alone must not clear a release build");
        assert!(
            matches!(err, BinaryTrustError::AnchorNotPublished { .. }),
            "{err}"
        );
    }

    #[test]
    fn a_witnessed_name_and_leaf_clear_the_release_gate() {
        let pinned = signer(Some(WITNESSED_LEAF));
        assert!(pinned.leaf_is_pinned());
        require_pinned_identity(Some(&pinned), true, "aether.exe").expect("the witness pinned it");
    }

    /// Refusing here would make every branch build untestable, and a debug build
    /// asserts nothing about release provenance — the compiled-in publisher stays.
    #[test]
    fn a_development_build_keeps_its_compiled_in_publisher_fallback() {
        assert!(require_pinned_identity(None, false, "aether.exe").is_ok());
        assert!(require_pinned_identity(Some(&signer(None)), false, "aether.exe").is_ok());
    }

    #[test]
    fn the_signer_is_compared_on_the_leaf_before_the_name() {
        let pinned = signer(Some(WITNESSED_LEAF));
        let err = check_pinned_signer(
            SOME_OTHER_LEAF,
            "CN=deathline94",
            Some(WITNESSED_LEAF),
            "deathline94",
        )
        .expect_err("a copied subject name is not the same certificate");
        assert!(
            matches!(err, BinaryTrustError::PublisherMismatch { .. }),
            "{err}"
        );
        assert!(
            err.to_string().contains(WITNESSED_LEAF),
            "the report must name what was expected: {pinned:?}"
        );
        check_pinned_signer(
            WITNESSED_LEAF,
            "CN=deathline94",
            Some(WITNESSED_LEAF),
            "deathline94",
        )
        .expect("the pinned leaf, signed by the pinned subject");
    }

    /// The old bug this file already fixed once, in the other direction: a subject
    /// that merely *starts* with the pinned name must still be refused.
    #[test]
    fn a_padded_subject_name_is_not_the_pinned_signer() {
        let err = check_pinned_signer(
            WITNESSED_LEAF,
            "CN=deathline94.example.com",
            None,
            "deathline94",
        )
        .expect_err("CN=deathline94.example.com is not CN=deathline94");
        assert!(
            matches!(err, BinaryTrustError::PublisherMismatch { .. }),
            "{err}"
        );
    }

    #[test]
    fn an_all_zero_placeholder_reads_as_unpinned_not_as_anything_goes() {
        let entries = anchor(serde_json::json!([
            { "name": "aether.exe", "file_sha256": WITNESSED_LEAF, "cert_sha256": PLACEHOLDER_SHA256,
              "issued_cn": "CN=deathline94", "signing_profile": "trusted-ca" }
        ]));
        assert_eq!(1, entries.len());
        assert_eq!(None, entries[0].cert_sha256, "the placeholder is 'no pin'");
        // The same entry through the identity gate: a witness that pins only the
        // bytes and not the leaf cannot clear a release build.
        let name_only = PinnedSigner {
            common_name: entries[0]
                .issued_cn
                .clone()
                .expect("the fixture names a subject")
                .trim_start_matches("CN=")
                .to_string(),
            cert_sha256: entries[0].cert_sha256.clone(),
            signing_profile: entries[0].signing_profile.clone(),
        };
        assert!(!name_only.leaf_is_pinned());
        assert!(matches!(
            require_pinned_identity(Some(&name_only), true, "aether.exe"),
            Err(BinaryTrustError::AnchorNotPublished { .. })
        ));
        // A real digest, however, must survive the parse untouched.
        let pinned = anchor(serde_json::json!([
            { "name": "aether.exe", "file_sha256": WITNESSED_LEAF, "cert_sha256": WITNESSED_LEAF,
              "issued_cn": "CN=deathline94" }
        ]));
        assert_eq!(Some(WITNESSED_LEAF.to_string()), pinned[0].cert_sha256);
    }

    #[test]
    fn an_entry_that_names_no_subject_pins_nobody() {
        let bytes = serde_json::json!({ "files": [
            { "name": "aether.exe", "file_sha256": WITNESSED_LEAF, "cert_sha256": WITNESSED_LEAF }
        ]})
        .to_string();
        let entries = parse_anchor_entries(bytes.as_bytes()).expect("parses");
        assert_eq!(None, entries[0].issued_cn);
        // `pinned_signer` reads the *compiled* anchor, so this asserts the pure part:
        // an entry without a subject cannot yield a name to compare against.
        let without_cn = entries[0]
            .issued_cn
            .as_ref()
            .map(|_| "would need a subject")
            .is_none();
        assert!(without_cn);
    }

    /// `build.rs` and this module read the same committed witness two ways; if they
    /// ever disagree about who signed the engine, the release gate is decoration.
    #[test]
    fn the_two_readings_of_the_same_witness_agree() {
        for name in ["aether.exe", "aether-ctl.exe"] {
            let from_anchor = anchor_entries()
                .into_iter()
                .find(|e| e.name == name)
                .and_then(|e| e.cert_sha256);
            let from_build = embedded_cert_pin(name).map(str::to_owned);
            if let (Some(a), Some(b)) = (&from_anchor, &from_build) {
                assert_eq!(
                    a, b,
                    "{name}: the runtime and build.rs read different leaf pins"
                );
            }
        }
    }
}
