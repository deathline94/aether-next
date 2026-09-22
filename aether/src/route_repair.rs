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
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::error::{AetherError, Result};

/// Bump when the journal layout changes; an older version is upgraded, never
/// guessed at.
pub const JOURNAL_VERSION: u32 = 1;

/// The prefixes Aether installs as its split default, plus the peer escape.
pub const SPLIT_DEFAULTS_V4: [&str; 2] = ["0.0.0.0/1", "128.0.0.0/1"];
pub const SPLIT_DEFAULTS_V6: [&str; 2] = ["::/1", "8000::/1"];

/// Whether a journal's holder is still running.
///
/// `Unknown` is a first-class answer and is never collapsed into `Dead`: every
/// consumer treats it as "do not mutate", because taking a route away from a live
/// tunnel is the exact failure this module exists to prevent, while leaving a
/// stale route is recoverable on the next start.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Liveness {
    Alive,
    Dead,
    Unknown,
}

/// T044 — how long the routing table keeps our entries *without* being told to.
///
/// This is a **backstop for a killed process**, never the primary teardown path:
/// [`crate::tun_win`] removes these routes explicitly on every clean disconnect,
/// and a journal replay does it for a crashed one. A lifetime is only the third
/// net — it exists so that a process killed hard (`TASKKILL /F`, job-object
/// termination, a blue screen mid-session) cannot leave the machine black-holed
/// indefinitely. 90 s is long enough that the 30 s refresh
/// ([`ROUTE_BACKSTOP_REFRESH_INTERVAL`] plus the shell's own cold start) cannot
/// miss twice in a row, short enough that a lost refresh costs a hiccup rather
/// than a broken network. It is *not* a substitute for the journal: an on-link
/// route that ages out silently takes traffic direct, which is the opposite of
/// what the user asked for.
pub const ROUTE_BACKSTOP_LIFETIME: &str = "00:01:30";
/// T044 — how often a live session re-arms the backstop above.
pub const ROUTE_BACKSTOP_REFRESH_INTERVAL: Duration = Duration::from_secs(30);

/// How a single route removal is allowed to select its target.
///
/// `Refuse` is a first-class outcome: it is what happens when the journal is
/// too old or too damaged to say *where* the route came from. Refusing leaves a
/// stale route in place, which is recoverable; guessing deletes a working
/// tunnel, which is not.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Scope {
    /// Remove only on the interface we recorded installing on, and only a route
    /// whose next hop is the one we recorded. This is the only shape that can
    /// name a route unambiguously, so it is preferred wherever both keys exist:
    /// an interface index alone is a *shared* identifier — a coexisting VPN's
    /// split default can sit on the same physical NIC as our peer escape.
    ByInterface {
        if_index: u32,
        next_hop: Option<Ipv4Addr>,
    },
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
    /// `next_hop` is the *recorded* hop, so a removal can be pinned to interface
    /// and hop at once. `None` means the journal never recorded a hop for this
    /// entry and the removal is interface-scoped only.
    Interface {
        if_index: u32,
        #[serde(default)]
        next_hop: Option<String>,
    },
    NextHop {
        next_hop: String,
    },
    Refused {
        why: String,
    },
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

// T042b — there used to be an `AdapterBefore` field here, "the pre-existing
// adapter state that must be put back". Both production writers passed
// `before: None`, nothing ever read it, and the only adapter whose DNS, metric
// or MTU this process changes is the WinTUN adapter it created — for which the
// correct inverse is *automatic*, not a snapshot. The field described state the
// engine never touches while advertising a guarantee no code path could keep, so
// it is deleted rather than implemented: filling it in would need a new query
// surface (reads this engine does not have, over FFI or a shell-out) and a
// restore path that writes a third-party adapter's numbers back — a larger
// host-mutation risk than the unreachable guarantee it replaces.
///
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
    /// Which boot of the machine wrote this, folded into the wall clock by
    /// [`boot_id`]. `0` means "a journal from before per-owner journals existed",
    /// which is exactly the pid-reuse case [`combine_liveness`] has to be careful
    /// with. Never trusted as an identity on its own — see [`decide_owner_exclusivity`].
    #[serde(default)]
    pub boot_id: u64,
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
            let recorded_hop = e.next_hop.parse::<Ipv4Addr>().ok();
            let scope = if e.if_index != 0 {
                // Interface key present: pin the hop too whenever we recorded one.
                Scope::ByInterface {
                    if_index: e.if_index,
                    next_hop: recorded_hop,
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
            } else if let Some(ip) = recorded_hop {
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
                    next_hop: gateway_hop,
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
                        next_hop: tunnel_hop,
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
            .filter(|p| render_removal_command(p).is_some())
            .count()
    }

    /// Should a journal left on disk be treated as abandoned?
    ///
    /// `holder` is injected so the rule is testable: the shipped bug was a
    /// `tasklist` *substring* match, where pid `4` matched the memory and
    /// session columns of unrelated rows and a long-dead holder looked alive
    /// forever, so stale routes were never cleaned.
    ///
    /// Only a *demonstrated* death qualifies. `Liveness::Unknown` leaves the
    /// routes alone: the journal stays on disk, so the next start tries again,
    /// whereas a wrong "dead" takes a working tunnel's routes out from under it.
    pub fn is_abandoned(&self, holder: Liveness) -> bool {
        self.creator_pid != 0 && holder == Liveness::Dead
    }
}

impl From<Scope> for ScopeKind {
    fn from(s: Scope) -> Self {
        match s {
            Scope::ByInterface { if_index, next_hop } => ScopeKind::Interface {
                if_index,
                next_hop: next_hop.map(|ip| ip.to_string()),
            },
            Scope::ByNextHop { next_hop } => ScopeKind::NextHop {
                next_hop: next_hop.to_string(),
            },
            Scope::Refuse { why } => ScopeKind::Refused { why: why.into() },
        }
    }
}

/// T035 — is exactly this pid present in the text `tasklist` printed?
///
/// The shipped version asked for the pid and then substring-searched the whole
/// output, so pid `4` matched the working-set column (`1,234 K`), the session
/// number, or another image's pid, and a long-dead journal holder looked alive
/// forever — its routes were never cleaned and the machine stayed black-holed.
/// This parses the **PID column only**, and answers [`Liveness::Unknown`] rather
/// than guessing when the text is not a shape it recognises.
///
/// Two real shapes are accepted:
/// * CSV (`tasklist /FO CSV /NH`): `"aether.exe","472","Console","1","12,340 K"`
/// * the default table: `aether.exe  472 Console  1  12,340 K`
pub fn liveness_from_tasklist(output: &str, pid: u32) -> Liveness {
    let mut saw_a_data_row = false;
    for raw in output.lines() {
        let line = raw.trim();
        if line.is_empty() || line.chars().all(|c| matches!(c, '=' | '-' | ' ' | '\t')) {
            continue;
        }
        if line.starts_with("INFO:") {
            // The only banner a pid-filtered query prints when nothing matched.
            if line.to_ascii_lowercase().contains("no tasks") {
                return Liveness::Dead;
            }
            continue;
        }
        // Column 1 is the pid in both shapes: it is the *second* CSV field
        // (image name is first) and the second whitespace token of a table row.
        let field = if line.starts_with('"') {
            csv_field(line, 1)
        } else {
            line.split_whitespace().nth(1)
        };
        let Some(field) = field else { continue };
        let Ok(candidate) = field.trim_matches('"').replace(',', "").parse::<u32>() else {
            // Header row (`PID`), or a column order this reader does not know.
            continue;
        };
        saw_a_data_row = true;
        if candidate == pid {
            return Liveness::Alive;
        }
    }
    if saw_a_data_row {
        Liveness::Dead
    } else {
        Liveness::Unknown
    }
}

/// Zero-indexed field of a CSV row, honouring double quotes so a comma inside an
/// image name or a `12,340 K` memory column cannot shift the pid into view.
fn csv_field(line: &str, want: usize) -> Option<&str> {
    let mut index = 0usize;
    let mut rest = line;
    loop {
        let (field, tail) = if let Some(body) = rest.strip_prefix('"') {
            match body.find('"') {
                Some(end) => (&body[..end], Some(&body[end + 1..])),
                None => (body, None),
            }
        } else {
            match rest.find(',') {
                Some(end) => (&rest[..end], Some(&rest[end + 1..])),
                None => (rest, None),
            }
        };
        if index == want {
            return Some(field);
        }
        let tail = tail?;
        index += 1;
        rest = tail.strip_prefix(',').unwrap_or(tail);
    }
}

/// Fold "when was this record written" with "does the pid exist right now".
///
/// A record written clearly before this boot started cannot belong to a live
/// process: the pid it names has either been recycled or has not existed since.
/// That is the only liveness answer that needs no process query at all, and it is
/// what makes pid reuse safe. The 300 s slack means a wall-clock adjustment (NTP
/// stepping the clock backwards after the journal was written) can never turn a
/// live holder into a dead one — the wrong direction here deletes routes that a
/// running tunnel is using.
pub fn combine_liveness(created_unix: u64, this_boot_unix: u64, probe: Liveness) -> Liveness {
    const SLACK_SECS: u64 = 300;
    if created_unix != 0 && this_boot_unix > created_unix.saturating_add(SLACK_SECS) {
        return Liveness::Dead;
    }
    probe
}

// ---------------------------------------------------------------------------
// Rendering: the only place a journal becomes command text.
//
// Removal and lifetime-refresh share one selector renderer on purpose. Two
// copies of "how do I name the route I created" is how a checker ends up
// validating a string the writer never wrote, and here the two copies would
// disagree about how tightly a mutation is scoped.
// ---------------------------------------------------------------------------

/// Action verb that takes a route out of the table.
pub const REMOVE_ROUTE_ACTION: &str =
    "Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue";

/// T044 — action verb that re-arms the 90 s backstop on an existing route.
pub fn refresh_lifetime_action() -> String {
    format!(
        "Set-NetRoute -ValidLifetime '{ROUTE_BACKSTOP_LIFETIME}' \
         -PreferredLifetime '{ROUTE_BACKSTOP_LIFETIME}' -ErrorAction SilentlyContinue"
    )
}

/// Which mutation a scoped selector is being built for.
///
/// An enum rather than a `&str` parameter: the verb is the one piece of the
/// rendered command that is not derived from journal data, so letting a caller
/// hand it over as text would put an unchecked string straight into PowerShell.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RouteAction {
    Remove,
    RefreshLifetime,
}

impl RouteAction {
    fn verb(self) -> String {
        match self {
            RouteAction::Remove => REMOVE_ROUTE_ACTION.to_string(),
            RouteAction::RefreshLifetime => refresh_lifetime_action(),
        }
    }
}

/// Defense-in-depth: reject any interpolated value that could break out of a
/// single-quoted PowerShell string literal. Inputs here are typed IPs and a
/// constant adapter name, so this should never fire in practice; it guards
/// against future call sites passing attacker-influenced strings into scripts.
pub fn ps_literal_is_safe(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, ' ' | '-' | '_' | '.' | ':'))
}

/// A CIDR is not a `ps_literal_is_safe` candidate — it legitimately contains `/`
/// — so it gets its own, equally boring, check.
fn cidr_is_safe(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | ':' | '/'))
}

/// `journal` + `action` → one scoped pipeline, or `None` when nothing may be run.
///
/// `None` is the safety property, not an error path: an entry that carries
/// neither an interface index nor a next hop we recorded cannot be distinguished
/// from the split default of a coexisting OpenVPN/Cisco session, so no text is
/// produced for it at all.
pub fn render_scoped_command(entry: &PlannedRemoval, action: RouteAction) -> Option<String> {
    let action = action.verb();
    let cidr = as_cidr(&entry.destination, &entry.mask)?;
    if !cidr_is_safe(&cidr) {
        log::error!(
            "[route-repair] cannot express {:?}/{:?} as a prefix; refusing",
            entry.destination,
            entry.mask
        );
        return None;
    }
    let selector = match &entry.scope {
        // T031: an entry whose interface key is zero has no interface scope. The
        // removal is refused here as well as in `removal_plan`, so a legacy or
        // hand-edited journal cannot reach `Remove-NetRoute` unscoped.
        ScopeKind::Interface { if_index: 0, .. } => {
            log::error!("[route-repair] refusing {cidr}: journal entry has no interface index");
            return None;
        }
        ScopeKind::Interface { if_index, next_hop } => {
            let mut guards = vec![format!("$_.InterfaceIndex -eq {if_index}")];
            match next_hop.as_deref() {
                Some(hop) if ps_literal_is_safe(hop) => {
                    guards.push(format!("$_.NextHop -eq '{hop}'"))
                }
                Some(hop) => {
                    log::error!("[route-repair] refusing {cidr}: rejected next-hop {hop:?}");
                    return None;
                }
                None => {}
            }
            format!(
                "Get-NetRoute -DestinationPrefix '{cidr}' -InterfaceIndex {if_index} \
                 -ErrorAction SilentlyContinue |\n  Where-Object {{ {} }}",
                guards.join(" -and ")
            )
        }
        ScopeKind::NextHop { next_hop } if ps_literal_is_safe(next_hop) => format!(
            "Get-NetRoute -DestinationPrefix '{cidr}' -ErrorAction SilentlyContinue |\n  \
             Where-Object {{ $_.NextHop -eq '{next_hop}' }}"
        ),
        ScopeKind::NextHop { next_hop } => {
            log::error!("[route-repair] refusing {cidr}: rejected next-hop {next_hop:?}");
            return None;
        }
        ScopeKind::Refused { why } => {
            log::error!("[route-repair] refusing to remove {cidr}: {why}");
            return None;
        }
    };
    Some(format!("{selector} |\n  {action}"))
}

/// T031 — the removal statement for one planned removal, or `None`.
pub fn render_removal_command(entry: &PlannedRemoval) -> Option<String> {
    render_scoped_command(entry, RouteAction::Remove)
}

/// T044 — the backstop re-arm for one planned removal, or `None`.
pub fn render_lifetime_refresh_command(entry: &PlannedRemoval) -> Option<String> {
    render_scoped_command(entry, RouteAction::RefreshLifetime)
}

fn render_for(journal: &RouteJournal, action: RouteAction) -> Vec<String> {
    journal
        .removal_plan()
        .iter()
        .filter_map(|p| render_scoped_command(p, action))
        .collect()
}

/// Every scoped `Remove-NetRoute` this journal permits.
pub fn removal_commands(journal: &RouteJournal) -> Vec<String> {
    render_for(journal, RouteAction::Remove)
}

/// Every scoped `Set-NetRoute -ValidLifetime` this journal permits (T044).
pub fn lifetime_refresh_commands(journal: &RouteJournal) -> Vec<String> {
    render_for(journal, RouteAction::RefreshLifetime)
}

/// Undo what `configure_adapter_ip` set on the tunnel NIC — pinned resolvers and
/// `InterfaceMetric 1` — so a lingering dead adapter cannot keep hijacking name
/// resolution. Returns nothing for an alias that is not a safe literal.
pub fn adapter_reset_commands(adapter_alias: &str) -> Vec<String> {
    if !ps_literal_is_safe(adapter_alias) {
        log::error!(
            "[route-repair] refusing to reset adapter config for unsafe alias {adapter_alias:?}"
        );
        return Vec::new();
    }
    vec![
        format!("Set-DnsClientServerAddress -InterfaceAlias '{adapter_alias}' -ResetServerAddresses -ErrorAction SilentlyContinue"),
        format!("Set-NetIPInterface -InterfaceAlias '{adapter_alias}' -AutomaticMetric Enabled -ErrorAction SilentlyContinue"),
    ]
}

/// What a teardown will actually do, and the tally the log line reports.
///
/// The tally is produced by the same pass that renders the commands, so "N
/// issued, M refused" cannot drift from what was built — the failure mode of the
/// shipped code, which counted a plan and then rendered it under a different set
/// of rules.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Teardown {
    pub commands: Vec<String>,
    pub removals: usize,
    pub refused: usize,
}

/// T032 — everything a teardown has to do, in commands for **one** shell.
///
/// The adapter reset is folded in rather than run as its own `powershell.exe`
/// because a cold PowerShell start is 1-2 s and the supervisor's grace window is
/// 5 s: at three spawns the last one simply never happened, which is how a
/// disconnect used to leave the NIC's DNS pinned to a dead tunnel.
pub fn teardown_plan(journal: &RouteJournal, adapter_alias: &str) -> Teardown {
    let planned = journal.removal_plan();
    let mut commands = Vec::with_capacity(planned.len() + 2);
    let mut removals = 0usize;
    for entry in &planned {
        if let Some(command) = render_removal_command(entry) {
            commands.push(command);
            removals += 1;
        }
    }
    commands.extend(adapter_reset_commands(adapter_alias));
    Teardown {
        commands,
        removals,
        refused: planned.len().saturating_sub(removals),
    }
}

/// The commands of [`teardown_plan`], for callers that only execute.
pub fn teardown_commands(journal: &RouteJournal, adapter_alias: &str) -> Vec<String> {
    teardown_plan(journal, adapter_alias).commands
}

/// One script, one process. The `$ErrorActionPreference` is deliberately
/// `SilentlyContinue`: a teardown that aborts on the first missing route leaves
/// the rest of the host state behind.
pub fn powershell_script(commands: &[String]) -> String {
    let mut script = String::from("$ErrorActionPreference = 'SilentlyContinue'\n");
    for command in commands {
        script.push_str(command);
        script.push('\n');
    }
    script
}

// ---------------------------------------------------------------------------
// Ownership: who is allowed to mutate the host at all (T036).
// ---------------------------------------------------------------------------

/// Who wrote a journal. `boot_id` is what makes the pid meaningful: a pid alone
/// gets reused, and a reused pid is how a new instance inherits an old
/// instance's belief that it owns the routing table.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct JournalOwner {
    pub creator_pid: u32,
    pub boot_id: u64,
}

/// One journal found on disk, with its holder's liveness already resolved.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnershipRecord {
    pub owner: JournalOwner,
    pub tun_if_index: u32,
    pub holder: Liveness,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MutationVerdict {
    Proceed,
    Refuse {
        why: &'static str,
        owner: JournalOwner,
    },
}

/// T036 — may this process install routes, given the journals already on disk?
///
/// A second engine used to overwrite the single shared journal, so the first
/// instance kept running against a record that no longer described it while the
/// second instance's teardown deleted prefixes the *first* one installed. The
/// answer is not to coordinate the two: it is for the newcomer to refuse. A
/// refused connect is visible and retryable; a deleted tunnel is neither.
///
/// `Liveness::Unknown` refuses too — an unreadable holder is treated as a live
/// one, which is the only direction that cannot damage a running session.
pub fn decide_owner_exclusivity(
    records: &[OwnershipRecord],
    mine: &JournalOwner,
    my_tun_if: u32,
) -> MutationVerdict {
    for record in records {
        if record.owner == *mine {
            // Our own journal from earlier in this run: overwriting it is correct.
            continue;
        }
        if record.holder == Liveness::Dead {
            // Its holder is gone; the replay in `decide_replay` owns that one.
            continue;
        }
        if record.tun_if_index == 0 || my_tun_if == 0 || record.tun_if_index == my_tun_if {
            return MutationVerdict::Refuse {
                why: "another Aether journal already owns this tunnel interface",
                owner: record.owner.clone(),
            };
        }
    }
    MutationVerdict::Proceed
}

/// May the stale-route replay act on this journal?
///
/// T033: recovery runs unconditionally at startup now, so the guard that makes
/// that safe lives here rather than in the caller's control flow. Everything
/// except a demonstrated dead holder is left exactly as it is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Replay {
    Remove,
    LeaveAlone(&'static str),
}

pub fn decide_replay(
    journal: &RouteJournal,
    holder: Liveness,
    my_pid: u32,
    my_boot_unix: u64,
) -> Replay {
    if journal.creator_pid == 0 {
        return Replay::LeaveAlone("journal records no owner");
    }
    // "Same pid" only means "same process" within one boot. Pids are recycled, and
    // a journal's `created_unix` says which boot wrote it; nothing survives a
    // reboot, so a pre-boot journal is not ours however its pid compares. The
    // early pid-equality return used to fire *before* that was asked, so it threw
    // away the `Dead` verdict the caller had already derived from
    // [`combine_liveness`] and left the recycled case installed forever: never
    // replayed, never deleted, routes still black-holed.
    let ours_this_boot = journal.creator_pid == my_pid
        && combine_liveness(journal.created_unix, my_boot_unix, Liveness::Alive) == Liveness::Alive;
    if ours_this_boot {
        return Replay::LeaveAlone("journal is ours; this process is the holder");
    }
    match holder {
        Liveness::Dead => Replay::Remove,
        Liveness::Alive => Replay::LeaveAlone("holder is alive"),
        Liveness::Unknown => Replay::LeaveAlone("holder liveness could not be established"),
    }
}

/// This process, as a journal owner.
pub fn current_owner() -> JournalOwner {
    JournalOwner {
        creator_pid: std::process::id(),
        boot_id: boot_id(),
    }
}

/// Seconds-since-boot folded into the wall clock. Every journal written in the
/// same boot shares it, and a reboot cannot reproduce the previous value, so a
/// recycled pid cannot claim an earlier boot's journal.
pub fn boot_id() -> u64 {
    crate::trust::now_unix().saturating_sub(uptime_secs())
}

#[cfg(windows)]
fn uptime_secs() -> u64 {
    use windows_sys::Win32::System::SystemInformation::GetTickCount64;
    // `unsafe` because every kernel32 binding is an extern declaration.
    let millis = unsafe { GetTickCount64() };
    millis / 1000
}

#[cfg(not(windows))]
fn uptime_secs() -> u64 {
    // Only the Windows host-mutation path keys journals on this; reading
    // `/proc/uptime` keeps the pure logic exercised where it is tested.
    std::fs::read_to_string("/proc/uptime")
        .ok()
        .and_then(|raw| {
            raw.split_whitespace()
                .next()
                .and_then(|secs| secs.parse::<f64>().ok())
        })
        .map(|secs| secs as u64)
        .unwrap_or(0)
}

/// `%LOCALAPPDATA%\AetherNext` (or `%TEMP%`), the one place host-state files live.
///
/// OS environment fact, not app configuration: `runtime_env` only owns
/// `AETHER_*` keys, so routing this through it would return `None`.
#[allow(clippy::disallowed_methods)]
pub fn state_dir() -> Option<PathBuf> {
    let dir = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("TEMP").map(PathBuf::from))?;
    Some(dir.join("AetherNext"))
}

/// Per-owner journals live here so one instance's cleanup cannot unlink another's.
pub fn journal_dir() -> Option<PathBuf> {
    Some(state_dir()?.join("routes.d"))
}

/// T036 — this owner's own journal file. `None` only if a temp path is set but
/// empty, in which case a mutation would be unrecordable anyway and the caller
/// refuses to act.
pub fn journal_path_for(owner: &JournalOwner) -> Option<PathBuf> {
    let pid = owner.creator_pid;
    let boot = owner.boot_id;
    Some(journal_dir()?.join(format!("routes.{pid}-{boot:#018x}.journal.json")))
}

/// The pre-per-owner-journal single file, still replayed and still cleaned up.
///
/// A distinct file name from `tun-routes.json` deliberately: the latter is a
/// different schema, and reusing the name would let a legacy file be read as a v1
/// journal with all fields defaulted to zero — which is exactly how the
/// unscoped-deletion branch was reached.
pub fn journal_path() -> Option<PathBuf> {
    Some(state_dir()?.join("routes.journal.json"))
}

/// Who wrote a journal, as read from disk (T036).
pub fn owner_of(journal: &RouteJournal) -> JournalOwner {
    JournalOwner {
        creator_pid: journal.creator_pid,
        boot_id: journal.boot_id,
    }
}

/// Every journal on disk: ours, every other owner's, and the legacy single file.
pub fn list_journal_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();
    if let Some(dir) = journal_dir() {
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().into_owned();
                if name.starts_with("routes.") && name.ends_with(".journal.json") {
                    paths.push(entry.path());
                }
            }
        }
    }
    if let Some(legacy) = journal_path() {
        if legacy.exists() {
            paths.push(legacy);
        }
    }
    paths.sort();
    paths
}

/// A journal on disk with its holder's liveness resolved.
#[derive(Clone, Debug)]
pub struct StaleJournal {
    pub path: PathBuf,
    pub journal: RouteJournal,
    pub holder: Liveness,
}

/// Read every journal and answer, for each, whether its holder is running.
///
/// `probe` is injected: the process query is the part that cannot run in CI, and
/// the shipped version of it was the substring bug (T035). A file that cannot be
/// parsed is dropped here because [`RouteJournal::load_opt`] already preserved it
/// as `.corrupt` and logged it — it is never silently deleted.
pub fn scan_journals(this_boot_unix: u64, probe: impl Fn(u32) -> Liveness) -> Vec<StaleJournal> {
    let mut found = Vec::new();
    for path in list_journal_paths() {
        let journal = match RouteJournal::load_opt(&path) {
            Ok(Some(j)) => j,
            Ok(None) => continue,
            Err(e) => {
                log::error!("[route-repair] cannot read {}: {e}", path.display());
                continue;
            }
        };
        let probed = probe(journal.creator_pid);
        let holder = combine_liveness(journal.created_unix, this_boot_unix, probed);
        found.push(StaleJournal {
            path,
            journal,
            holder,
        });
    }
    found
}

/// Unlink a journal we are done with, treating "already gone" as success.
pub fn remove_journal_file(path: &std::path::Path) {
    if let Err(e) = std::fs::remove_file(path) {
        if e.kind() != std::io::ErrorKind::NotFound {
            log::error!(
                "[route-repair] could not remove journal {}: {e}",
                path.display()
            );
        }
    }
}

/// The replay loop, policy-complete and free of any host call.
///
/// `probe` answers "is this pid running" (a process query the caller owns);
/// `effect` performs the removal (the caller owns PowerShell too). Everything in
/// between — which journals exist, which of them are abandoned, which files may
/// be unlinked — is decided here, so it is the part CI can check.
pub fn replay_abandoned_journals(
    probe: impl Fn(u32) -> Liveness,
    effect: &dyn Fn(&RouteJournal),
) -> usize {
    let me = std::process::id();
    let this_boot = boot_id();
    let mut handled = 0usize;
    for stale in scan_journals(this_boot, &probe) {
        match decide_replay(&stale.journal, stale.holder, me, this_boot) {
            Replay::Remove => {
                log::warn!(
                    "[route-repair] recovering routes abandoned by dead pid {}",
                    stale.journal.creator_pid
                );
                effect(&stale.journal);
                handled += 1;
                remove_journal_file(&stale.path);
            }
            Replay::LeaveAlone(why) => {
                if stale.journal.creator_pid == 0 {
                    // Unattributable: nothing may be removed for it, and keeping
                    // the file would hide a real journal from the next start.
                    log::warn!("[route-repair] dropping {}", stale.path.display());
                    remove_journal_file(&stale.path);
                } else {
                    log::info!(
                        "[route-repair] leaving {} alone: {why}",
                        stale.path.display()
                    );
                }
            }
        }
    }
    handled
}

/// T033 — host-state repair as a single, callable entry point.
///
/// Recovery used to hang off `tun_win::spawn`, i.e. it only ever ran when the
/// user entered TUN mode, so routes left by a crashed run stayed in the table
/// indefinitely on a GUI that never opens TUN. It is now run from the engine's
/// own startup (`cli::run`) and can be run from anywhere else through this name.
/// Calling it is always safe: [`decide_replay`] refuses to act on anything whose
/// holder is not demonstrably gone, and the whole replay takes the host-mutation
/// lock, so a concurrent session is never raced.
pub fn repair_host_state_now() {
    #[cfg(windows)]
    crate::tun_win::recover_stale_routes();
    #[cfg(not(windows))]
    log::debug!("[route-repair] nothing to repair: host network state is Windows-only");
}

/// Async form, for a shell that reaches for it from inside a runtime: the work
/// blocks on process launches, so it must not run on an async thread.
pub async fn repair_host_state() {
    if let Err(e) = tokio::task::spawn_blocking(repair_host_state_now).await {
        log::error!("[route-repair] startup repair did not run: {e}");
    }
}

fn split_prefix(p: &str) -> (String, String) {
    let (dest, len) = p.split_once('/').unwrap_or((p, "0"));
    let len: u32 = len.parse().unwrap_or(0);
    (dest.into(), prefix_len_to_mask(len))
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

/// Persist the journal atomically, refusing to continue if it cannot be
/// written: an unjournalled mutation is an unrecoverable one.
pub fn write_journal(path: &std::path::Path, j: &RouteJournal) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| AetherError::HostState(format!("create journal dir: {e}")))?;
    }
    let body = serde_json::to_vec_pretty(j)
        .map_err(|e| AetherError::HostState(format!("encode journal: {e}")))?;
    let tmp = sibling_with_suffix(
        path,
        &format!(".{}.{}.tmp", std::process::id(), rand::random::<u32>()),
    );
    std::fs::write(&tmp, body)
        .map_err(|e| AetherError::HostState(format!("write journal: {e}")))?;
    std::fs::rename(&tmp, path)
        .map_err(|e| AetherError::HostState(format!("rename journal into place: {e}")))?;
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
            boot_id: 0x1111_2222_3333_4444,
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
                ScopeKind::Interface { if_index, .. } => assert_ne!(*if_index, 0),
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
        for p in &plan {
            // Every recorded entry carried both keys, so every removal is pinned
            // to an interface *and* the hop we installed it with.
            match &p.scope {
                ScopeKind::Interface { if_index, next_hop } => {
                    assert_ne!(*if_index, 0);
                    assert!(
                        next_hop.is_some(),
                        "recorded hop must scope the removal too"
                    );
                }
                other => panic!("unexpected scope for a recorded journal: {other:?}"),
            }
            assert!(render_removal_command(p).is_some());
        }
        assert_eq!(j.actionable_removals(), 4);
    }

    /// The shipped liveness check was `stdout.contains(pid)`, where pid `4`
    /// matches memory/session columns of unrelated rows.
    #[test]
    fn abandoned_only_when_holder_is_confirmed_dead() {
        let j = journal();
        assert!(
            !j.is_abandoned(Liveness::Alive),
            "live holder keeps its routes"
        );
        assert!(
            !j.is_abandoned(Liveness::Unknown),
            "an unestablished answer never authorises a deletion"
        );
        assert!(
            j.is_abandoned(Liveness::Dead),
            "dead holder's routes are stale"
        );
        let mut no_pid = j;
        no_pid.creator_pid = 0;
        assert!(
            !no_pid.is_abandoned(Liveness::Dead),
            "unknown owner is not evidence of death"
        );
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
        assert_eq!(
            as_cidr("0.0.0.0", "255.0.0.0").as_deref(),
            Some("0.0.0.0/8")
        );
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
