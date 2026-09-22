//! Binary and peer trust primitives.
//!
//! This module exists because the same trust policy used to live in three
//! places that disagreed with each other (`tls.rs`, `masque_h2.rs` and the
//! desktop shell), which is how a "fail-closed" hash check ended up unable to
//! ever fail. Two decisions are encoded here:
//!
//! * [`VerifyPolicy`] is passed *explicitly* to every TLS builder. There is no
//!   ambient environment variable that can switch verification off, and the
//!   insecure variant does not exist at all in a release binary.
//! * [`AnchorSet`] is loaded from a committed, human-reviewed file rather than
//!   being computed at build time from the artifact being shipped, so the pin
//!   is an independent witness instead of a tautology.
//!
//! ## Why no process here is ever launched across a token boundary
//!
//! TUN needs administrator rights, and there are two ways to get them: elevate the
//! app, or leave the app unelevated and spawn the worker with `Start-Process -Verb
//! RunAs` / `ShellExecuteW("runas")`. This project uses the first and forbids the
//! second, and the reason is a Windows semantics fact rather than a UX preference.
//!
//! The shell puts the engine in a kill-on-close **job object** so the tunnel can
//! never outlive the UI. `AssignProcessToJobObject` cannot put a process into its
//! caller's job *across a token boundary*: the elevated child is created by the
//! kernel in the administrator's session and the assignment fails. The result is
//! the worst combination available — an engine holding routes, the system proxy and
//! a Wintun adapter, running with a token that nothing in this app can terminate.
//! Kill-on-close becomes kill-on-what-the-user-remembers, and a crashed UI leaves a
//! black-holed machine behind.
//!
//! So: elevation is requested up front (`AppInfo::application_manifest` /
//! "Run as administrator"), never per-child. `elevation::is_elevated()` gates TUN
//! and refuses rather than escalating mid-session, and gate 13 in
//! `scripts/verify-invariants.mjs` fails CI if a `-Verb RunAs`, `ShellExecute`,
//! `CreateProcessWithTokenW` or `LogonUser` call ever appears in either binary.

use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::error::{AetherError, Result};

/// Schema tag for `packaging/trust/engine-trust.json`.
pub const ANCHOR_SCHEMA: u32 = 1;
/// A pin may not be valid for longer than this, so a stale committed file
/// fails loudly rather than silently trusting a rotated-away key forever.
pub const MAX_PIN_VALIDITY_SECS: u64 = 180 * 24 * 60 * 60;
/// Clocks ahead of us by more than this are treated as hostile, not skewed.
pub const CLOCK_SLACK_SECS: u64 = 300;

/// One Subject Public Key Info pin, bound to a host and an expiry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pin {
    /// Lowercase hex SHA-256 of the leaf's `subjectPublicKeyInfo`.
    pub spki_sha256: String,
    /// Unix seconds after which this pin must no longer be honoured.
    pub expires_unix: u64,
    /// Optional leaf certificate SHA-256, for diagnostics and key rotation.
    #[serde(default)]
    pub cert_sha256: Option<String>,
}

/// Pins for one identity.
///
/// Both knobs below are *per host* on purpose. The audit defect was that
/// `masque_h2.rs` disabled hostname checking **globally** to work around one
/// fronted edge, which removed name binding from every peer the process could
/// reach. Tightening either flag is now a data change to
/// `packaging/trust/masque-pins.json`, not a code change.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PinSet {
    pub host: String,
    #[serde(default)]
    pub require_hostname: bool,
    /// Build and validate the full chain against the system/embedded roots.
    ///
    /// **There is no default, on purpose.** `#[serde(default)]` here meant that
    /// omitting the key in the shipped JSON silently turned chain validation off
    /// for that host, and BoringSSL's precomputed `ok` was then discarded by the
    /// verify callback — pins-only on every live connection. A pin file that does
    /// not say what it means is now a load error, which makes the decision a
    /// reviewed line in the file rather than an absence.
    pub require_chain: bool,
    pub pins: Vec<Pin>,
}

/// A release-time generated, committed set of trusted release binaries.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AnchorSet {
    pub version: u32,
    pub generated_unix: u64,
    pub files: Vec<AnchorFile>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AnchorFile {
    pub name: String,
    /// Lowercase hex SHA-256 of the signed file as published.
    pub file_sha256: String,
    /// Lowercase hex SHA-256 of the signer's leaf certificate DER.
    pub cert_sha256: String,
    /// Subject of the signing certificate, for logs only — never a decision.
    #[serde(default)]
    pub issued_cn: String,
}

/// The committed, human-reviewed MASQUE pin file, baked into the binary.
pub const MASQUE_PINS_JSON: &str = include_str!("../../packaging/trust/masque-pins.json");

/// Validated pin sets for the consumer MASQUE edges.
///
/// Loaded from the committed file rather than a byte literal in `consts.rs` so
/// a rotation is a reviewable one-line diff, and so "empty pins" can never be
/// mistaken for "trust everyone" — see [`active_pins`].
///
/// A load failure yields an empty set rather than a panic, which fails closed at
/// the one place that matters (`tls::install_pin_verification` refuses a host with
/// no pin set). It is *not* a loud startup signal, so a session must call
/// [`require_valid_masque_pins`] first: that is what turns a bad
/// `masque-pins.json` into a refusal to start instead of a connection error
/// several steps later.
pub fn masque_pin_sets() -> &'static [PinSet] {
    static SETS: OnceLock<Vec<PinSet>> = OnceLock::new();
    SETS.get_or_init(|| {
        load_pins(MASQUE_PINS_JSON, now_unix()).unwrap_or_else(|e| {
            log::error!("[trust] masque-pins.json is unusable, no pins loaded: {e}");
            Vec::new()
        })
    })
}

/// Refuse to run a session on an unusable pin file. Called once at session start
/// so the operator sees which witness is broken and why.
pub fn require_valid_masque_pins() -> Result<()> {
    let sets = masque_pin_sets();
    if sets.is_empty() {
        return Err(AetherError::Tls(
            "packaging/trust/masque-pins.json did not load: refusing to start a session \
             that could not pin its peer"
                .into(),
        ));
    }
    // Re-check expiry against the *current* clock: the cached set was validated
    // the first time it was loaded, and a long-lived process must not run past
    // the rotation deadline it printed at startup.
    active_pins(sets, now_unix())
}

/// On-disk shape of `packaging/trust/masque-pins.json`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PinFile {
    #[serde(default)]
    pub version: u32,
    pub hosts: Vec<PinSet>,
}

/// Load and validate the per-host pin file.
pub fn load_pins(json: &str, now_unix: u64) -> Result<Vec<PinSet>> {
    let file: PinFile =
        serde_json::from_str(json).map_err(|e| AetherError::Other(format!("pin file: {e}")))?;
    if file.version != 1 {
        return Err(AetherError::Other(format!(
            "unsupported pin file schema {} (expected 1)",
            file.version
        )));
    }
    active_pins(&file.hosts, now_unix)?;
    Ok(file.hosts)
}

/// Parsed and validated anchor file.
///
/// Validation is deliberately strict: an empty file, an unknown schema or a
/// blank digest is an error, because the defect this replaces was `build.rs`
/// silently emitting *no* digest entries and a later check happily passing on
/// an empty allow-list.
pub fn load_anchors(json: &str) -> Result<AnchorSet> {
    let set: AnchorSet = serde_json::from_str(json)
        .map_err(|e| AetherError::Other(format!("trust anchors: {e}")))?;
    if set.version != ANCHOR_SCHEMA {
        return Err(AetherError::Other(format!(
            "unsupported trust anchor schema {} (expected {ANCHOR_SCHEMA})",
            set.version
        )));
    }
    if set.files.is_empty() {
        return Err(AetherError::Other(
            "trust anchor file lists no binaries; refusing to run an empty allow-list".into(),
        ));
    }
    for f in &set.files {
        if !is_hex_sha256(&f.file_sha256) || !is_hex_sha256(&f.cert_sha256) {
            return Err(AetherError::Other(format!(
                "trust anchor for {:?} has a non-SHA-256 digest",
                f.name
            )));
        }
    }
    Ok(set)
}

/// Validate a per-host pin set: non-empty, well-formed, unexpired, and not
/// longer-lived than policy allows.
pub fn active_pins(sets: &[PinSet], now_unix: u64) -> Result<()> {
    if sets.is_empty() {
        return Err(AetherError::Tls(
            "no pinned hosts configured; refusing to connect unverified".into(),
        ));
    }
    for s in sets {
        if s.pins.is_empty() {
            return Err(AetherError::Tls(format!(
                "host {} has zero SPKI pins",
                s.host
            )));
        }
        if s.pins.len() < 2 {
            log::warn!(
                "[trust] host {} has {} pin(s); rotation needs at least 2 (live + next key)",
                s.host,
                s.pins.len()
            );
        }
        for p in &s.pins {
            if !is_hex_sha256(&p.spki_sha256) {
                return Err(AetherError::Tls(format!(
                    "host {} has a malformed SPKI pin",
                    s.host
                )));
            }
        }
        // An expired pin is normal mid-rotation; *no* live pins is fatal.
        let live = s.pins.iter().filter(|p| p.expires_unix > now_unix).count();
        if live == 0 {
            return Err(AetherError::Tls(format!(
                "every SPKI pin for host {} has expired (latest expiry {}); refresh {}",
                s.host,
                s.pins.iter().map(|p| p.expires_unix).max().unwrap_or(0),
                "packaging/trust/masque-pins.json"
            )));
        }
        if live < 2 {
            log::warn!(
                "[trust] host {} has only {live} unexpired pin(s); rotation needs a second key pinned in advance",
                s.host
            );
        }
        if let Some(max) = s.pins.iter().map(|p| p.expires_unix).max() {
            if max > now_unix + MAX_PIN_VALIDITY_SECS {
                log::warn!(
                    "[trust] pin for {} is valid longer than policy allows (expiry {max})",
                    s.host
                );
            }
        }
    }
    Ok(())
}

pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default()
}

pub fn is_hex_sha256(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b) || (b'A'..=b'F').contains(&b))
}

/// How a connection shall be verified. Passed explicitly; never ambient.
///
/// There is deliberately no predicate here for "is the chain still validated":
/// the single `match` in `tls::build_config` is the whole policy, and a second
/// function reporting on it (which the previous `requires_chain_validation` was)
/// has no caller and therefore no way to be wrong loudly.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerifyPolicy<'a> {
    /// Full chain verification against `anchors` **plus** an SPKI pin match.
    /// The only variant constructible in a release build.
    Pinned(&'a [PinSet]),
    /// Chain verification without pins, for read-only diagnostics that must
    /// never carry tunnel traffic (`fingerprint_h3`).
    ReadOnlyProbe,
    /// No verification. Debug builds only; the variant does not exist in a
    /// release binary, so no environment variable can reach it either.
    #[cfg(debug_assertions)]
    Insecure { reason: &'static str },
}

/// SHA-256 of a file, lowercase hex. Used for both digest and trust checks.
pub fn file_sha256_hex(path: &std::path::Path) -> Result<String> {
    use std::io::Read;
    let mut f = std::fs::File::open(path)
        .map_err(|e| AetherError::Other(format!("open {} for digest: {e}", path.display())))?;
    let mut ctx = ring::digest::Context::new(&ring::digest::SHA256);
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = f
            .read(&mut buf)
            .map_err(|e| AetherError::Other(format!("read {} for digest: {e}", path.display())))?;
        if n == 0 {
            break;
        }
        ctx.update(&buf[..n]);
    }
    Ok(hex::encode(ctx.finish()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pin(spki: &str, expires: u64) -> Pin {
        Pin {
            spki_sha256: spki.into(),
            expires_unix: expires,
            cert_sha256: None,
        }
    }

    const A: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const B: &str = "2222222222222222222222222222222222222222222222222222222222222222";

    #[test]
    fn empty_anchor_list_is_rejected() {
        let json = r#"{"version":1,"generated_unix":1,"files":[]}"#;
        assert!(
            load_anchors(json).is_err(),
            "an empty allow-list must not pass"
        );
    }

    #[test]
    fn unknown_anchor_schema_is_rejected() {
        let json = r#"{"version":99,"generated_unix":1,"files":[{"name":"aether.exe","file_sha256":"aa","cert_sha256":"bb"}]}"#;
        assert!(load_anchors(json).is_err());
    }

    #[test]
    fn malformed_digest_is_rejected() {
        let json = r#"{"version":1,"generated_unix":1,"files":[{"name":"aether.exe","file_sha256":"deadbeef","cert_sha256":"bb"}]}"#;
        assert!(load_anchors(json).is_err());
    }

    /// `active_pins` is the loader gate; host scoping of the digests themselves is
    /// enforced where a connection is built, by `tls::install_pin_verification`
    /// refusing a host with no pin set — see `tests/tls_pin_chain.rs`, which runs
    /// against real certificates.
    #[test]
    fn an_expired_pin_set_is_a_hard_error_not_a_fallback() {
        let sets = vec![PinSet {
            host: "edge.example".into(),
            require_hostname: true,
            require_chain: false,
            pins: vec![pin(A, 100), pin(B, 100)],
        }];
        assert!(
            active_pins(&sets, 1_000).is_err(),
            "an all-expired set must be a hard error, not a fallback"
        );
    }

    /// The exact shape of the shipped file that used to be silent: an omitted
    /// `require_chain` decoded to `false`, which discarded BoringSSL's chain
    /// verdict on every live connection. It is a load error now.
    #[test]
    fn a_pin_host_that_does_not_say_whether_to_validate_the_chain_is_rejected() {
        let silent = r#"{"version":1,"hosts":[{"host":"edge.example","require_hostname":false,
            "pins":[{"spki_sha256":"1111111111111111111111111111111111111111111111111111111111111111","expires_unix":1805500800},
                    {"spki_sha256":"2222222222222222222222222222222222222222222222222222222222222222","expires_unix":1805500800}]}]}"#;
        let err = load_pins(silent, 1).expect_err("an absent require_chain must not default");
        assert!(
            err.to_string().contains("require_chain"),
            "the error must name the missing field: {err}"
        );

        let spoken = silent.replace(
            "\"require_hostname\":false,",
            "\"require_hostname\":false,\"require_chain\":true,",
        );
        let sets = load_pins(&spoken, 1).expect("the same file with the field present");
        assert!(sets[0].require_chain);
    }

    #[test]
    fn empty_pin_set_is_an_error_not_trust_nothing_off() {
        let sets: Vec<PinSet> = vec![];
        assert!(active_pins(&sets, 1).is_err());
    }

    #[test]
    fn committed_pin_and_anchor_files_parse() {
        // Guards the two shipped witnesses against drifting away from these
        // structs: a schema edit that silently unparseable-ifies the committed
        // files would otherwise only be noticed on a user's machine.
        let pins = include_str!("../../packaging/trust/masque-pins.json");
        let hosts = load_pins(pins, now_unix()).expect("masque-pins.json must parse and be live");
        assert!(!hosts.is_empty());
        for h in &hosts {
            assert!(
                h.pins.iter().any(|p| p.expires_unix > now_unix()),
                "{} has no unexpired pin",
                h.host
            );
        }

        let anchors = include_str!("../../packaging/trust/engine-trust.json");
        let set = load_anchors(anchors).expect("engine-trust.json must parse");
        assert!(!set.files.is_empty());
    }

    #[test]
    fn hex_sha256_shape() {
        assert!(is_hex_sha256(A));
        assert!(!is_hex_sha256(&A[..63]));
        assert!(!is_hex_sha256("zz"));
    }
}
