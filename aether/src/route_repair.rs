//! Host network state: the intent journal and the removal *policy*.
//!
//! Split out of `tun_win.rs` on purpose. Everything here is pure and
//! platform-neutral so the safety property that actually matters — "Aether
//! never removes a route it did not create" — is unit-testable on any machine,
//! without admin rights, a WinTUN adapter, or a second VPN installed. The
//! effecting half stays in `tun_win.rs`.
//!
//! The defect this replaces: `remove_routes()` scoped its deletion by interface
//! index *only when the index was non-zero*, and the persisted state struct was
//! `#[serde(default)]`, so any legacy, truncated or hand-edited state file
//! produced zero indexes and the code then deleted `0.0.0.0/1`, `128.0.0.0/1`,
//! `::/1` and `8000::/1` from **every** interface — byte-for-byte the shape of a
//! coexisting OpenVPN/Cisco split tunnel. A missing field silently turned into
//! the most destructive branch available.

use std::net::Ipv4Addr;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::error::{AetherError, Result};

/// Bump when the journal layout changes; an older version is upgraded, never
/// guessed at.
pub const JOURNAL_VERSION: u32 = 1;

/// The prefixes Aether installs as its split default, plus the peer escape.
pub const SPLIT_DEFAULTS_V4: [&str; 2] = ["0.0.0.0/1", "128.0.0.0/1"];
pub const SPLIT_DEFAULTS_V6: [&str; 2] = ["::/1", "8000::/1"];

/// How a single route removal is allowed to select its target.
///
/// `Refuse` is a first-class outcome: it is what happens when the journal is
/// too old or too damaged to say *where* the route came from. Refusing leaves a
/// stale route in place, which is recoverable; guessing deletes a working
/// tunnel, which is not.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Scope {
    /// Remove only on the interface we recorded installing on.
    ByInterface { if_index: u32 },
    /// Interface identity unknown: remove only routes whose next-hop is this
    /// address, i.e. only routes that can only have come from us.
    ByNextHop { next_hop: Ipv4Addr },
    /// Nothing safe can be said — do not remove anything.
    Refuse { why: &'static str },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlannedRemoval {
    pub destination: String,
    pub mask: String,
    pub scope: ScopeKind,
}

/// Serialisable mirror of [`Scope`] for plans that get logged or asserted on.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ScopeKind {
    Interface { if_index: u32 },
    NextHop { next_hop: String },
    Refused { why: String },
}

/// One route we created, as recorded before we created it.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteIntent {
    /// Dotted destination, e.g. `0.0.0.0`.
    pub destination: String,
    /// Dotted prefix mask, e.g. `128.0.0.0`.
    pub mask: String,
    /// Next hop we installed it with (`0.0.0.0` for an on-link route).
    pub next_hop: String,
    /// Interface index we installed it on (0 = unknown at write time).
    #[serde(default)]
    pub if_index: u32,
    /// 2 = IPv4, 23 = IPv6 (`MIB_IPFORWARD_FAMILY`).
    #[serde(default = "default_family")]
    pub family: u32,
}

fn default_family() -> u32 {
    2
}

/// Pre-existing adapter state that must be put back.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdapterBefore {
    #[serde(default)]
    pub dns_servers: Vec<String>,
    #[serde(default)]
    pub interface_metric: Option<u32>,
    #[serde(default)]
    pub mtu_bytes: Option<u32>,
}

/// The intent journal. Written **before** the first mutation.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteJournal {
    #[serde(default)]
    pub version: u32,
    #[serde(default)]
    pub created_unix: u64,
    /// Installing process. Used only for liveness, never as a scoping key.
    #[serde(default)]
    pub creator_pid: u32,
    /// Adapter alias, stable across reindexing (`Aether`).
    #[serde(default)]
    pub tun_alias: String,
    #[serde(default)]
    pub tun_if_index: u32,
    #[serde(default)]
    pub phys_if_index: u32,
    /// Physical default gateway at install time — the peer escape's next hop.
    #[serde(default)]
    pub gateway: String,
    /// Tunnel address we assigned ourselves; the only next-hop we may match on
    /// when removing split defaults without an interface index.
    #[serde(default)]
    pub tunnel_ipv4: String,
    /// Edge peer address, as a /32 host route via `gateway`.
    #[serde(default)]
    pub peer_ipv4: String,
    #[serde(default)]
    pub entries: Vec<RouteIntent>,
    #[serde(default)]
    pub before: Option<AdapterBefore>,
}

impl RouteJournal {
    /// Parse a journal, tolerating a missing or legacy file as `None` rather
    /// than as an error: repair must still be able to run on a file it cannot
    /// fully understand, and it must do so by refusing to guess.
    pub fn load_opt(path: &std::path::Path) -> Result<Option<RouteJournal>> {
        let bytes = match std::fs::read(path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        if bytes.is_empty() {
            return Ok(None);
        }
        match serde_json::from_slice::<RouteJournal>(&bytes) {
            Ok(j) => Ok(Some(j)),
            Err(e) => {
                // A corrupt journal is preserved for post-mortems; the earlier
                // behaviour of renaming it away destroyed the evidence and the
                // repair path in one move.
                let bad = sibling_with_suffix(path, ".corrupt");
                log::error!(
                    "[route-repair] unreadable journal at {}: {e}; preserving as {}",
                    path.display(),
                    bad.display()
                );
                let _ = std::fs::rename(path, &bad);
                Ok(None)
            }
        }
    }

    /// Every removal we are permitted to perform, with an explicit scope each.
    ///
    /// Rules (contracts/host-state-contract.md INV-1/INV-2):
    /// * a recorded, non-zero interface index scopes the removal to that NIC;
    /// * otherwise the removal is scoped to the journal's own next hop;
    /// * if neither is known, the removal is refused, not global.
    pub fn removal_plan(&self) -> Vec<PlannedRemoval> {
        let tunnel_hop = self
            .tunnel_ipv4
            .parse::<Ipv4Addr>()
            .ok()
            .filter(|ip| !ip.is_unspecified());
        let gateway_hop = self
            .gateway
            .parse::<Ipv4Addr>()
            .ok()
            .filter(|ip| !ip.is_unspecified());

        let mut plan = Vec::new();

        // 1. Routes we recorded creating.
        for e in &self.entries {
            let scope = if e.if_index != 0 {
                Scope::ByInterface {
                    if_index: e.if_index,
                }
            } else if e.next_hop == "0.0.0.0" || e.next_hop.is_empty() {
                // On-link split default with no interface recorded: the only
                // safe discriminator left is our own tunnel address.
                match tunnel_hop {
                    Some(ip) => Scope::ByNextHop { next_hop: ip },
                    None => Scope::Refuse {
                        why: "no interface index and no tunnel address recorded",
                    },
                }
            } else if let Ok(ip) = e.next_hop.parse::<Ipv4Addr>() {
                Scope::ByNextHop { next_hop: ip }
            } else {
                Scope::Refuse {
                    why: "recorded next hop is not an address",
                }
            };
            plan.push(PlannedRemoval {
                destination: e.destination.clone(),
                mask: e.mask.clone(),
                scope: scope.into(),
            });
        }

        // 2. The peer escape host route, even if `entries` predates it.
        if !self.peer_ipv4.is_empty() {
            let scope = if self.phys_if_index != 0 {
                Scope::ByInterface {
                    if_index: self.phys_if_index,
                }
            } else {
                match gateway_hop {
                    Some(ip) => Scope::ByNextHop { next_hop: ip },
                    None => Scope::Refuse {
                        why: "peer route has no recorded interface or gateway",
                    },
                }
            };
            plan.push(PlannedRemoval {
                destination: self.peer_ipv4.clone(),
                mask: "255.255.255.255".into(),
                scope: scope.into(),
            });
        }

        // 3. Split defaults that predate per-entry recording entirely.
        if self.entries.is_empty() && self.peer_ipv4.is_empty() {
            for dest in SPLIT_DEFAULTS_V4 {
                let (destination, mask) = split_prefix(dest);
                let scope = if self.tun_if_index != 0 {
                    Scope::ByInterface {
                        if_index: self.tun_if_index,
                    }
                } else {
                    match tunnel_hop {
                        Some(ip) => Scope::ByNextHop { next_hop: ip },
                        None => Scope::Refuse {
                            why: "legacy journal with no interface, no next hop",
                        },
                    }
                };
                plan.push(PlannedRemoval {
                    destination,
                    mask,
                    scope: scope.into(),
                });
            }
        }

        plan
    }

    /// Count of removals this journal actually permits, for logging.
    pub fn actionable_removals(&self) -> usize {
        self.removal_plan()
            .iter()
            .filter(|p| !matches!(p.scope, ScopeKind::Refused { .. }))
            .count()
    }

    /// Should a journal left on disk be treated as abandoned?
    ///
    /// `alive` is injected so the rule is testable: the shipped bug was a
    /// `tasklist` *substring* match, where pid `4` matched the memory and
    /// session columns of unrelated rows and a long-dead holder looked alive
    /// forever, so stale routes were never cleaned.
    pub fn is_abandoned(&self, alive: bool) -> bool {
        self.creator_pid != 0 && !alive
    }
}

impl From<Scope> for ScopeKind {
    fn from(s: Scope) -> Self {
        match s {
            Scope::ByInterface { if_index } => ScopeKind::Interface { if_index },
            Scope::ByNextHop { next_hop } => ScopeKind::NextHop {
                next_hop: next_hop.to_string(),
            },
            Scope::Refuse { why } => ScopeKind::Refused { why: why.into() },
        }
    }
}

fn split_prefix(p: &str) -> (String, String) {
    let (dest, len) = p.split_once('/').unwrap_or((p, "0"));
    let len: u32 = len.parse().unwrap_or(0);
    (
        dest.into(),
        prefix_len_to_mask(len),
    )
}

/// Dotted prefix length → netmask. Only /1 and /0 matter today, but writing the
/// general form beats the old code's `"128.0.0.0"` for *both* halves, which was
/// right by luck.
pub fn prefix_len_to_mask(len: u32) -> String {
    if len == 0 {
        return "0.0.0.0".into();
    }
    let len = len.min(32);
    let bits = u32::MAX << (32 - len);
    Ipv4Addr::from(bits).to_string()
}

/// Dotted netmask → prefix length, best effort.
///
/// Returns `None` for a non-contiguous mask, which the caller must treat as
/// "cannot express this as a prefix" rather than guessing a length: a wrong
/// length here selects the wrong routes, which is the failure this module
/// exists to prevent.
pub fn mask_to_prefix_len(mask: &str) -> Option<u8> {
    let octets: Vec<u8> = mask
        .split('.')
        .map(|o| o.trim().parse::<u8>().ok())
        .collect::<Option<_>>()?;
    if octets.len() != 4 {
        return None;
    }
    let bits = u32::from_be_bytes([octets[0], octets[1], octets[2], octets[3]]);
    // A valid netmask is a contiguous run of ones starting at the MSB. Compare
    // against the canonical form rather than probing `!bits + 1`, which overflows
    // for the all-ones inversion that `/0` (0.0.0.0) produces.
    let ones = bits.count_ones();
    let canonical = if ones == 0 {
        0u32
    } else {
        u32::MAX << (32 - ones)
    };
    if bits != canonical {
        return None;
    }
    Some(ones as u8)
}

/// `destination` + `mask` → CIDR prefix, or `None` if it cannot be expressed.
pub fn as_cidr(destination: &str, mask: &str) -> Option<String> {
    if destination.contains(':') {
        // IPv6 routes carry their own prefix length.
        return Some(destination.to_string());
    }
    mask_to_prefix_len(mask).map(|len| format!("{destination}/{len}"))
}

fn sibling_with_suffix(path: &std::path::Path, suffix: &str) -> PathBuf {
    let mut name = path
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "routes".into());
    name.push_str(suffix);
    path.with_file_name(name)
}

/// `%LOCALAPPDATA%\AetherNext\routes.journal.json`.
///
/// A new file name, deliberately: the old `tun-routes.json` is a different
/// schema, and reusing the name would let a legacy file be read as a v1
/// journal with all fields defaulted to zero — which is exactly how the
/// unscoped-deletion branch was reached.
pub fn journal_path() -> Option<PathBuf> {
    let dir = crate::runtime_env::var("LOCALAPPDATA")
        .map(PathBuf::from)
        .or_else(|| crate::runtime_env::var("TEMP").map(PathBuf::from))?;
    Some(dir.join("AetherNext").join("routes.journal.json"))
}

/// Persist the journal atomically, refusing to continue if it cannot be
/// written: an unjournalled mutation is an unrecoverable one.
pub fn write_journal(path: &std::path::Path, j: &RouteJournal) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| AetherError::Other(format!("create journal dir: {e}")))?;
    }
    let body = serde_json::to_vec_pretty(j)
        .map_err(|e| AetherError::Other(format!("encode journal: {e}")))?;
    let tmp = sibling_with_suffix(path, &format!(".{}.{}.tmp", std::process::id(), rand::random::<u32>()));
    std::fs::write(&tmp, body).map_err(|e| AetherError::Other(format!("write journal: {e}")))?;
    std::fs::rename(&tmp, path)
        .map_err(|e| AetherError::Other(format!("rename journal into place: {e}")))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn journal() -> RouteJournal {
        RouteJournal {
            version: JOURNAL_VERSION,
            created_unix: 1,
            creator_pid: 4242,
            tun_alias: "Aether".into(),
            tun_if_index: 44,
            phys_if_index: 11,
            gateway: "192.168.1.1".into(),
            tunnel_ipv4: "172.16.0.2".into(),
            peer_ipv4: "162.159.193.1".into(),
            entries: vec![
                RouteIntent {
                    destination: "0.0.0.0".into(),
                    mask: "128.0.0.0".into(),
                    next_hop: "0.0.0.0".into(),
                    if_index: 44,
                    family: 2,
                },
                RouteIntent {
                    destination: "128.0.0.0".into(),
                    mask: "128.0.0.0".into(),
                    next_hop: "0.0.0.0".into(),
                    if_index: 44,
                    family: 2,
                },
                RouteIntent {
                    destination: "162.159.193.1".into(),
                    mask: "255.255.255.255".into(),
                    next_hop: "192.168.1.1".into(),
                    if_index: 11,
                    family: 2,
                },
            ],
            before: Some(AdapterBefore {
                dns_servers: vec!["192.168.1.1".into()],
                interface_metric: Some(25),
                mtu_bytes: Some(1500),
            }),
        }
    }

    /// The audit's headline defect: a legacy/zeroed journal must never be able
    /// to produce an unscoped prefix deletion.
    #[test]
    fn zeroed_identifiers_never_yield_global_deletion() {
        let mut j = journal();
        j.tun_if_index = 0;
        j.phys_if_index = 0;
        for e in &mut j.entries {
            e.if_index = 0;
        }
        let plan = j.removal_plan();
        assert!(!plan.is_empty(), "a legacy journal still plans cleanup");
        for p in &plan {
            match &p.scope {
                // Every removal must name either an interface or a next hop that
                // can only be ours.
                ScopeKind::Interface { if_index } => assert_ne!(*if_index, 0),
                ScopeKind::NextHop { next_hop } => {
                    assert!(
                        next_hop == "172.16.0.2" || next_hop == "192.168.1.1",
                        "removal matched on an address we did not create: {next_hop}"
                    );
                }
                ScopeKind::Refused { .. } => {}
            }
        }
        assert!(
            !plan
                .iter()
                .any(|p| matches!(p.scope, ScopeKind::Refused { .. })
                    && (p.destination == "0.0.0.0" || p.destination == "128.0.0.0")),
            "split defaults must be removable, but only next-hop scoped"
        );
    }

    #[test]
    fn totally_unknown_journal_refuses_instead_of_guessing() {
        let j = RouteJournal::default();
        let plan = j.removal_plan();
        assert!(
            plan.iter()
                .all(|p| matches!(p.scope, ScopeKind::Refused { .. })),
            "no identifiers at all must refuse every removal: {plan:?}"
        );
        assert_eq!(j.actionable_removals(), 0);
    }

    #[test]
    fn recorded_journal_scopes_by_interface() {
        let j = journal();
        let plan = j.removal_plan();
        assert_eq!(plan.len(), 4, "3 entries + peer escape");
        assert!(plan
            .iter()
            .all(|p| matches!(p.scope, ScopeKind::Interface { .. })));
        assert_eq!(j.actionable_removals(), 4);
    }

    /// The shipped liveness check was `stdout.contains(pid)`, where pid `4`
    /// matches memory/session columns of unrelated rows.
    #[test]
    fn abandoned_only_when_holder_is_confirmed_dead() {
        let j = journal();
        assert!(!j.is_abandoned(true), "live holder keeps its routes");
        assert!(j.is_abandoned(false), "dead holder's routes are stale");
        let mut no_pid = j;
        no_pid.creator_pid = 0;
        assert!(!no_pid.is_abandoned(false), "unknown owner is not evidence of death");
    }

    #[test]
    fn mask_math_is_correct() {
        assert_eq!(prefix_len_to_mask(1), "128.0.0.0");
        assert_eq!(prefix_len_to_mask(0), "0.0.0.0");
        assert_eq!(prefix_len_to_mask(32), "255.255.255.255");
        assert_eq!(prefix_len_to_mask(24), "255.255.255.0");
        assert_eq!(split_prefix("128.0.0.0/1").1, "128.0.0.0");
    }

    #[test]
    fn mask_roundtrip() {
        for len in [0u8, 1, 8, 24, 25, 31, 32] {
            let mask = prefix_len_to_mask(len as u32);
            assert_eq!(
                mask_to_prefix_len(&mask).unwrap(),
                len,
                "{len} -> {mask} -> back"
            );
        }
    }

    #[test]
    fn non_contiguous_mask_is_refused_not_guessed() {
        // 255.0.255.0 is not a netmask. Guessing a prefix length here would
        // select the wrong routes — the exact class of bug this module removes.
        assert_eq!(mask_to_prefix_len("255.0.255.0"), None);
        assert_eq!(mask_to_prefix_len("256.0.0.0"), None);
        assert_eq!(mask_to_prefix_len(""), None);
        // 255.0.0.0 *is* contiguous ones — it is /8, not a malformed mask.
        assert_eq!(as_cidr("0.0.0.0", "255.0.0.0").as_deref(), Some("0.0.0.0/8"));
        assert_eq!(as_cidr("0.0.0.0", "255.0.255.0"), None);
    }

    #[test]
    fn cidr_form_is_what_the_executor_needs() {
        assert_eq!(
            as_cidr("0.0.0.0", "128.0.0.0").as_deref(),
            Some("0.0.0.0/1")
        );
        assert_eq!(
            as_cidr("162.159.193.1", "255.255.255.255").as_deref(),
            Some("162.159.193.1/32")
        );
        assert_eq!(as_cidr("::/1", "").as_deref(), Some("::/1"));
    }

    #[test]
    fn json_roundtrip_preserves_scoping_identity() {
        let j = journal();
        let s = serde_json::to_string(&j).unwrap();
        let back: RouteJournal = serde_json::from_str(&s).unwrap();
        assert_eq!(j, back);
        assert_eq!(back.removal_plan(), j.removal_plan());
    }

    #[test]
    fn empty_journal_file_is_absent_not_fatal() {
        let dir = std::env::temp_dir().join(format!("aether-jr-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("routes.journal.json");
        std::fs::write(&p, b"").unwrap();
        assert!(RouteJournal::load_opt(&p).unwrap().is_none());
        std::fs::write(&p, b"{ not json").unwrap();
        assert!(RouteJournal::load_opt(&p).unwrap().is_none());
        // Corrupt input is preserved rather than overwritten.
        assert!(dir.join("routes.journal.json.corrupt").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_then_read_journal() {
        let dir = std::env::temp_dir().join(format!("aether-jw-{}", std::process::id()));
        let p = dir.join("routes.journal.json");
        let j = journal();
        write_journal(&p, &j).unwrap();
        let back = RouteJournal::load_opt(&p).unwrap().expect("present");
        assert_eq!(j, back);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
