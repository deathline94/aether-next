//! Session orchestrator — owns the full lifecycle from protocol selection
//! through identity provisioning, endpoint discovery, tunnel execution, and
//! proxy teardown. `main.rs` is a thin entry-point that delegates here.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use crate::account;
use crate::aethernoize;
use crate::config;
use crate::consts;
use crate::dns;
use crate::engine_config::EngineConfig;
use crate::error::{AetherError, Result};
use crate::http_proxy;
use crate::lastconn;
use crate::masque_h2;
use crate::mtu;
use crate::netstack;
use crate::noize;
use crate::obfuscation;
use crate::prober;
use crate::quic;
use crate::routing_plane;
use crate::runtime_env;
use crate::session_event::{self, SessionEvent};
use crate::socks;
use crate::tls;
use crate::tunnel;
use crate::wireguard;

// ─── MTU helpers ────────────────────────────────────────────────────────────

/// How often a tunnel supervision loop says "still here". Must stay comfortably
/// below `session_event::HEARTBEAT_INTERVAL`, which is the window the pulse is
/// measured over.
const SUPERVISE_TICK: Duration = Duration::from_secs(2);

/// What warp-in-warp costs the inner packet: ~60 B of WireGuard encapsulation
/// on the outer leg plus ~60 B on the inner one.
const INNER_ENCAP_OVERHEAD: usize = 120;

/// The inner MTU for a given outer tunnel MTU.
///
/// The M12 floor was `v.max(1152.min(tm - 80))`: with an outer MTU of 1240 that
/// returned 1152 against a 1120-byte budget, so the floor *was* the overflow its
/// own comment called impossible. The re-clamp that followed (`budget.max(1152
/// .min(budget))`) could not change the answer in either direction — a floor can
/// never raise an MTU above the budget it is supposed to respect — so the 1152
/// preference is gone rather than re-clamped, and the budget is the whole rule.
/// No lower guard is put back: `mtu::env_override` already floors the outer
/// value at 576, so the smallest budget here is 456.
fn inner_mtu_for(tunnel_mtu: usize) -> usize {
    tunnel_mtu.saturating_sub(INNER_ENCAP_OVERHEAD)
}

/// MTU for a WireGuard-leg stack (plain WARP and the gool outer leg).
///
/// `mtu::resolve_mtu`'s `protocol` argument only steers the *first* probe: the
/// answer is cached in one process-wide slot shared with MASQUE, so a WireGuard
/// session that follows an H2 MASQUE connect is handed 1400 regardless of what it
/// asked for. `mtu.rs`'s own stated rule is that only MASQUE-over-TCP may use 1400
/// because "WireGuard outer packets add ~60B", so the rule is re-applied here
/// rather than giving a WG stack an MTU its encapsulation cannot carry. The root
/// fix is a per-protocol cache in `mtu.rs`.
async fn wireguard_mtu(ipv6_configured: bool) -> usize {
    /// WireGuard's own encap is 60-80 B, and the value `mtu.rs` calls "conservative
    /// (<=1280)" for this transport.
    const WIREGUARD_MAX_INNER_MTU: usize = 1280;
    let resolved = crate::mtu::resolve_mtu("wireguard", ipv6_configured).await;
    let capped = resolved.min(WIREGUARD_MAX_INNER_MTU);
    if capped != resolved {
        log::info!(
            "[+] WireGuard MTU capped to {capped} (was {resolved}): the value on record \
             was probed for a different transport"
        );
    }
    crate::mtu::clamp_for_ip_families(capped, ipv6_configured)
}

/// Detached-task guard (M12 fix): aborts its task on drop so leaked tunnels stop
/// pinging the edge after their owner fails or unwinds.
struct AbortOnDrop<T>(tokio::task::JoinHandle<T>);

impl<T> Drop for AbortOnDrop<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

impl<T> AbortOnDrop<T> {
    /// Resolve when the wrapped task does, without consuming the guard — the
    /// supervision select needs to await it while every other exit path still has
    /// to abort it. A guard whose task nobody can wait on is how a dead inner
    /// tunnel turned into a hung session.
    async fn done(&mut self) -> std::result::Result<T, tokio::task::JoinError> {
        (&mut self.0).await
    }
}

/// Active readiness gate (M12 fix): replaces the blind 1.5s sleep before the
/// gool inner tunnel. Any completed open_tcp outcome — success OR fast refusal —
/// proves the data plane round-trips; only a timeout means the handshake never
/// came up. Retries give boringtun time to finish under slow links.
async fn wait_stack_alive(stack: &netstack::StackHandle, label: &str) -> Result<()> {
    const ATTEMPTS: usize = 6;
    let dst: SocketAddr = "1.1.1.1:53".parse().unwrap();
    for attempt in 1..=ATTEMPTS {
        match tokio::time::timeout(Duration::from_secs(3), stack.open_tcp(dst)).await {
            // Opening a socket proves the stack is responsive; the handle must
            // then be closed. TcpSender has no Drop guard, so every probe leaked
            // a socket plus its buffers.
            Ok(Ok(conn)) => {
                let (tx, _rx) = conn.into_split();
                tx.close().await;
                log::info!("[+] {label} data plane accepting opens (attempt {attempt})");
                return Ok(());
            }
            // A refusal from our own stack ("netstack closed", "too many TCP
            // connections", "no free local ports") is the opposite of proof of
            // life, yet the old `Ok(_)` arm matched the Err variant too and a
            // dead stack satisfied the readiness gate.
            Ok(Err(ref e)) if local_stack_broken(&e.to_string()) => {
                log::error!("[-] {label} local stack refused the probe open ({e}); retrying");
            }
            // Refused *through* the tunnel: a packet went out and an answer came
            // back, so the data plane round-trips.
            Ok(Err(_)) => {
                log::info!("[+] {label} data plane round-trips (attempt {attempt})");
                return Ok(());
            }
            Err(_) => {
                log::warn!(
                    "[-] {label} data plane not ready (attempt {attempt}/{ATTEMPTS}); retrying"
                );
                tokio::time::sleep(Duration::from_millis(700)).await;
            }
        }
    }
    Err(AetherError::Other(format!(
        "{label} WireGuard data plane did not come up"
    )))
}

/// True when an open failure came from our own netstack rather than from the
/// remote end. A readiness gate must never conflate the two.
fn local_stack_broken(err: &str) -> bool {
    const LOCAL: &[&str] = &[
        "netstack closed",
        "netstack dropped",
        "too many TCP connections",
        "no free local ports",
    ];
    LOCAL.iter().any(|k| err.contains(k))
}

#[cfg(test)]
mod readiness_tests {
    use super::local_stack_broken;

    #[test]
    fn local_refusals_are_not_proof_of_life() {
        assert!(local_stack_broken("netstack dropped"));
        assert!(local_stack_broken("too many TCP connections"));
        assert!(local_stack_broken("no free local ports"));
    }

    #[test]
    fn remote_refusals_still_prove_a_round_trip() {
        assert!(!local_stack_broken("connection refused"));
        assert!(!local_stack_broken("timed out"));
        assert!(!local_stack_broken(""));
    }

    /// M12, as a number: the old floor turned a 1240-byte outer MTU into a
    /// 1152-byte inner one against a 1120-byte budget, so every full-size inner
    /// packet overflowed the encapsulation the comment claimed was safe.
    #[test]
    fn the_inner_mtu_never_exceeds_the_encapsulation_budget() {
        assert_eq!(super::inner_mtu_for(1240), 1120);
        assert_eq!(super::inner_mtu_for(1280), 1160);
        assert_eq!(super::inner_mtu_for(576), 456);
        for outer in [576, 1240, 1280, 1400, 1500, 65535] {
            assert!(
                super::inner_mtu_for(outer) + super::INNER_ENCAP_OVERHEAD <= outer,
                "outer {outer} produced an inner MTU the encapsulation cannot carry"
            );
        }
    }
}

// ─── Protocol ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Masque,
    WireGuard,
    WarpInWarp,
}

impl Protocol {
    /// The transport a name selects, defaulting to MASQUE.
    ///
    /// The default is deliberate but it is not silent: an unrecognised value
    /// (`AETHER_PROTOCOL=wiregrd`) used to fall through to MASQUE with nothing
    /// written down, which for a tool whose whole job is *which* path your traffic
    /// takes is the one substitution nobody should discover from a capture.
    pub fn parse(s: &str) -> Protocol {
        let name = s.trim().to_lowercase();
        match name.as_str() {
            "wg" | "wireguard" => Protocol::WireGuard,
            "gool" | "wiw" | "warp-in-warp" | "warpinwarp" => Protocol::WarpInWarp,
            "masque" | "masque-h2" | "masque-h3" | "h3" | "h2" | "" => Protocol::Masque,
            _ => {
                log::warn!(
                    "[+] unrecognised protocol {s:?}; running MASQUE - expected one of \
                     masque|wg|wireguard|gool|warp-in-warp"
                );
                Protocol::Masque
            }
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Protocol::Masque => "MASQUE",
            Protocol::WireGuard => "WireGuard",
            Protocol::WarpInWarp => "WARP-in-WARP (gool)",
        }
    }
}

// ─── Session entry ──────────────────────────────────────────────────────────

/// Product session entry — CLI is a thin adapter; GUI spawns this binary.
pub async fn run_session(cfg: EngineConfig) -> Result<()> {
    // Two things the rest of the session cannot recover from being wrong, checked
    // before any network call: the witness that authenticates the peer, and the
    // obfuscation profile the operator asked for. Both used to degrade silently —
    // an unreadable pin file left the transports with no pins at all and a later
    // connection error, and an unrecognised profile name quietly became `balanced`.
    crate::trust::require_valid_masque_pins()?;
    obfuscation::validate_profile_name(&cfg.noize)?;

    // Apply resolved config into a thread-safe, in-process store (S3 fix).
    // Downstream helpers read these via runtime_env::var, which falls back to
    // the real process environment. This avoids std::env::set_var, which is a
    // data race once the async runtime's worker threads are running.
    runtime_env::set("AETHER_NOIZE", &cfg.noize);
    runtime_env::set("AETHER_SCAN", &cfg.scan);
    runtime_env::set("AETHER_IP", &cfg.ip);
    if cfg.masque_http2 {
        runtime_env::set("AETHER_MASQUE_HTTP2", "1");
    }
    if cfg.tun {
        runtime_env::set("AETHER_TUN", "1");
    }

    let listen = cfg.socks;
    let http_listen = cfg.http;
    let base_config = cfg.config_path.clone();

    // Pulsed while the session runs; dropped (i.e. aborted) when run_session
    // returns, including on the error paths.
    let _heartbeat = session_event::start_heartbeat();
    session_event::set_phase(session_event::Phase::Identity);

    let protocol = if cfg.has_forced_peer() || runtime_env::var("AETHER_PROTOCOL").is_some() {
        Protocol::parse(&cfg.protocol)
    } else {
        select_protocol().await
    };

    match protocol {
        Protocol::Masque => {
            let config_path = masque_config_path(&base_config);
            let identity = load_or_provision_masque(&config_path).await?;
            log::info!(
                "[+] identity ready: device={} ipv4={} ipv6={}",
                identity.device_id,
                identity.ipv4,
                identity.ipv6
            );
            session_event::emit(SessionEvent::IdentityReady {
                device_id: identity.device_id.clone(),
                ipv4: identity.ipv4.clone(),
            });
            // Standalone H3 diagnostics: probe one edge across the SNI x header x
            // ECH matrix and exit. Enable with AETHER_H3_PROBE=<ip:port>.
            if let Some(target) = crate::runtime_env::var("AETHER_H3_PROBE") {
                match target.trim().parse::<SocketAddr>() {
                    Ok(edge) => {
                        let ech = resolve_ech().await;
                        return crate::h3_probe::run_probe(edge, &identity, ech).await;
                    }
                    Err(_) => log::warn!("[h3-probe] bad AETHER_H3_PROBE address: {target}"),
                }
            }
            // Phase 4 endpoint enumeration: fingerprint-scan a /24 or ip list for
            // MASQUE-capable edges (ext_connect + h3 datagram) and exit.
            if let Some(spec) = crate::runtime_env::var("AETHER_H3_FINGERPRINT") {
                return crate::h3_probe::run_fingerprint(&spec, &identity).await;
            }
            // H3 and H2 both hunt across the shared MASQUE pool (MASQUE_CIDRS + SEEDS)
            // over the tiered ports (443 -> 8443/4443/8095 -> 2408/500/1701/4500).
            // select_peer honors a forced AETHER_PEER and runs quick-reconnect first.
            // If an H3 scan comes up empty (e.g. every port DPI-dropped in this
            // environment), fall back to the API-assigned endpoint / known anycast VIP
            // so we still attempt a connect rather than aborting the session.
            let selection = match select_peer(
                &identity,
                protocol,
                &base_config,
                prober::WgSessionCache::new(),
            )
            .await
            {
                Ok(s) => s,
                Err(e) if scan_only() => {
                    // Standalone scanner: finding nothing is a completed scan, not a
                    // session error. Emit a terminal ScanDone so the GUI stops
                    // cleanly (and don't fabricate an anycast "selection").
                    log::warn!("[-] standalone scan found no reachable endpoint: {e}");
                    session_event::emit(SessionEvent::ScanDone {
                        addr: String::new(),
                        rtt: String::new(),
                        protocol: "masque".into(),
                        best_rtt_ms: None,
                    });
                    return Ok(());
                }
                Err(e) => return Err(e),
            };
            let peer = selection.peer;
            log::info!("[+] using cloudflare edge {peer}");
            session_event::emit(SessionEvent::EndpointSelected {
                addr: peer.to_string(),
                protocol: "masque".into(),
                rtt_ms: selection.best_rtt_ms(),
            });
            // Scan-only mode: report result and exit without tunnel.
            if scan_only() {
                session_event::set_phase(session_event::Phase::Scan);
                session_event::emit(SessionEvent::ScanDone {
                    addr: peer.to_string(),
                    rtt: selection.human_rtt(),
                    protocol: "masque".into(),
                    best_rtt_ms: selection.best_rtt_ms(),
                });
                return Ok(());
            }
            session_event::set_phase(session_event::Phase::Handshake);
            let ech = resolve_ech().await;
            let mut result =
                run_masque_tunnel(identity.clone(), peer, ech.clone(), listen, http_listen).await;
            // An ECH-specific failure used to retry the whole tunnel with ECH
            // *removed* on a single warning — for any error at all. A middlebox
            // that drops ECH ClientHellos therefore turned an opt-in privacy
            // control into cleartext SNI on every connect, permanently and
            // silently. The retry is now gated on an explicit decision.
            if let Err(e) = &result {
                if ech.is_some() && ech_related(e) {
                    if runtime_env::flag("AETHER_ECH_ALLOW_DOWNGRADE") {
                        log::warn!(
                            "[-] ECH-specific failure ({e}); downgrading to no-ECH because \
                             AETHER_ECH_ALLOW_DOWNGRADE is set — the SNI is visible on the wire"
                        );
                        result =
                            run_masque_tunnel(identity.clone(), peer, None, listen, http_listen)
                                .await;
                    } else {
                        // Not retried, and the message is what the user sees:
                        // `cli::run` turns a failed session into the terminal
                        // `SessionEvent::Error`, so this string *is* the event and
                        // naming the knob there is what makes the decision theirs.
                        return Err(AetherError::Ech(format!(
                            "the connect failed in a way that involves ECH ({e}). Refusing to \
                             retry with ECH stripped, which would send the SNI in cleartext. \
                             Set AETHER_ECH_ALLOW_DOWNGRADE=1 to accept that fallback, or \
                             AETHER_ECH=0 to stop using ECH deliberately."
                        )));
                    }
                }
            }
            // Feed the real connect outcome into the trust cache so endpoint
            // ranking learns from actual connections, not just scan reachability.
            let mutation = if result.is_ok() {
                crate::cache::record_success(&base_config, peer, true)
            } else {
                crate::cache::record_failure(&base_config, peer, true)
            };
            if mutation.was_skipped() {
                log::warn!(
                    "[cache] {} record for {peer} was skipped: another process holds the cache lock",
                    if result.is_ok() { "success" } else { "failure" }
                );
            }
            result
        }
        Protocol::WireGuard => {
            let config_path = warp_config_path(&base_config);
            let identity = load_or_provision_warp(&config_path).await?;
            log::info!(
                "[+] identity ready: device={} ipv4={} ipv6={}",
                identity.device_id,
                identity.ipv4,
                identity.ipv6
            );
            session_event::emit(SessionEvent::IdentityReady {
                device_id: identity.device_id.clone(),
                ipv4: identity.ipv4.clone(),
            });
            // Scan-only mode: select peer then report. A scan that finds nothing is
            // a completed scan, not a session error, so emit a terminal ScanDone
            // either way and let the GUI stop cleanly.
            if scan_only() {
                match select_peer(
                    &identity,
                    protocol,
                    &base_config,
                    prober::WgSessionCache::new(),
                )
                .await
                {
                    Ok(selection) => session_event::emit(SessionEvent::ScanDone {
                        addr: selection.peer.to_string(),
                        rtt: selection.human_rtt(),
                        protocol: "wireguard".into(),
                        best_rtt_ms: selection.best_rtt_ms(),
                    }),
                    Err(e) => {
                        log::warn!("[-] standalone WireGuard scan found no endpoint: {e}");
                        session_event::emit(SessionEvent::ScanDone {
                            addr: String::new(),
                            rtt: String::new(),
                            protocol: "wireguard".into(),
                            best_rtt_ms: None,
                        });
                    }
                }
                return Ok(());
            }
            session_event::set_phase(session_event::Phase::Handshake);
            run_wireguard(identity, listen, http_listen, &base_config).await
        }
        Protocol::WarpInWarp => {
            let primary_path = warp_config_path(&base_config);
            let secondary_path = derive_sibling_path(&primary_path, "secondary");
            let primary = load_or_provision_warp(&primary_path).await?;
            let secondary = load_or_provision_warp(&secondary_path).await?;
            log::info!(
                "[+] outer device={} ipv4={} | inner device={} ipv4={}",
                primary.device_id,
                primary.ipv4,
                secondary.device_id,
                secondary.ipv4
            );
            let selection = select_peer(
                &primary,
                Protocol::WireGuard,
                &base_config,
                prober::WgSessionCache::new(),
            )
            .await?;
            let peer = selection.peer;
            log::info!("[+] using cloudflare edge {peer} (outer)");
            session_event::emit(SessionEvent::EndpointSelected {
                addr: peer.to_string(),
                protocol: "gool".into(),
                rtt_ms: selection.best_rtt_ms(),
            });
            if scan_only() {
                session_event::emit(SessionEvent::ScanDone {
                    addr: peer.to_string(),
                    rtt: selection.human_rtt(),
                    protocol: "gool".into(),
                    best_rtt_ms: selection.best_rtt_ms(),
                });
                return Ok(());
            }
            session_event::set_phase(session_event::Phase::Handshake);
            run_warp_in_warp(primary, secondary, peer, listen, http_listen).await
        }
    }
}

// ─── Config path helpers ────────────────────────────────────────────────────

/// True when the engine is in scan-only mode (AETHER_SCAN_ONLY=1).
/// In this mode, the session discovers the best endpoint and exits without
/// establishing a tunnel.
fn scan_only() -> bool {
    crate::runtime_env::flag("AETHER_SCAN_ONLY")
}

fn noize_config() -> noize::NoizeConfig {
    obfuscation::masque_from_env()
}

fn aethernoize_config() -> aethernoize::AetherNoizeConfig {
    obfuscation::wg_from_env()
}

fn warp_config_path(base: &str) -> String {
    if let Some(p) = runtime_env::var("AETHER_WG_CONFIG") {
        return p;
    }
    base.to_string()
}

fn masque_config_path(base: &str) -> String {
    if let Some(p) = runtime_env::var("AETHER_MASQUE_CONFIG") {
        return p;
    }
    derive_sibling_path(base, "masque")
}

fn derive_sibling_path(base: &str, suffix: &str) -> String {
    let dir_end = base.rfind(['/', '\\']).map(|i| i + 1).unwrap_or(0);
    match base[dir_end..].rfind('.') {
        Some(rel) => {
            let dot = dir_end + rel;
            format!("{}-{}{}", &base[..dot], suffix, &base[dot..])
        }
        None => format!("{base}-{suffix}"),
    }
}

// ─── Identity provisioning ──────────────────────────────────────────────────

async fn load_or_provision_warp(config_path: &str) -> Result<account::Identity> {
    if let Some(identity) = config::load(config_path)? {
        log::info!("[+] loaded existing warp identity from {config_path}");
        return Ok(identity);
    }

    // Serialize provisioning across processes: a concurrent scan + connect must not
    // both register a device (device churn) or race the shared identity file.
    let _provision = crate::cache::provision_lock(config_path)?;
    if let Some(identity) = config::load(config_path)? {
        log::info!("[+] warp identity provisioned by a concurrent process; reusing");
        return Ok(identity);
    }

    log::info!("[+] no warp identity found; provisioning dedicated wireguard account");
    let identity =
        account::provision_wg(consts::DEFAULT_MODEL, consts::DEFAULT_LOCALE, None).await?;
    config::save(config_path, &identity)?;
    log::info!("[+] provisioned and saved new warp identity to {config_path}");
    Ok(identity)
}

async fn load_or_provision_masque(config_path: &str) -> Result<account::Identity> {
    // Fast path: a fully-enrolled identity is reusable without the provision lock.
    if let Some(identity) = config::load(config_path)? {
        if identity.can_run_masque() {
            log::info!(
                "[+] loaded existing masque identity from {config_path} (capability={:?})",
                identity.capability()
            );
            return Ok(identity);
        }
    }

    // Provisioning or enrollment is needed — serialize across processes so a
    // concurrent scan + connect don't both register a device (device churn) or
    // race the shared identity file.
    let _provision = crate::cache::provision_lock(config_path)?;

    // Re-check after acquiring the lock: another process may have just finished.
    if let Some(identity) = config::load(config_path)? {
        if identity.can_run_masque() {
            log::info!("[+] masque identity ready (provisioned by a concurrent process); reusing");
            return Ok(identity);
        }
        log::info!("[+] masque identity missing credentials; enrolling masque key");
        let (cert_pem, key_pem, masque_endpoint) =
            account::ensure_masque_enrolled(&identity).await?;
        // Assigned in place rather than rebuilt with `..identity`: an `Identity`
        // zeroizes on drop, so it cannot be partially moved out of.
        let mut identity = identity;
        identity.cert_pem = cert_pem;
        identity.key_pem = key_pem;
        identity.masque_endpoint = masque_endpoint;
        config::save(config_path, &identity)?;
        return Ok(identity);
    }

    log::info!("[+] no masque identity found; provisioning dedicated masque account");
    let identity =
        account::provision_wg(consts::DEFAULT_MODEL, consts::DEFAULT_LOCALE, None).await?;
    let (cert_pem, key_pem, masque_endpoint) = account::ensure_masque_enrolled(&identity).await?;
    let mut identity = identity;
    identity.cert_pem = cert_pem;
    identity.key_pem = key_pem;
    identity.masque_endpoint = masque_endpoint;
    config::save(config_path, &identity)?;
    log::info!("[+] provisioned and saved new masque identity to {config_path}");
    Ok(identity)
}

// ─── Endpoint selection ─────────────────────────────────────────────────────

/// What endpoint selection resolved to.
///
/// `rtt` is the measurement that proved the endpoint, or `None` when the peer was
/// forced from config and nothing was probed. A scan that ends without it must
/// say so instead of printing an empty RTT next to a real address.
struct Selection {
    peer: SocketAddr,
    rtt: Option<std::time::Duration>,
}

impl Selection {
    fn best_rtt_ms(&self) -> Option<f64> {
        self.rtt.map(|d| d.as_secs_f64() * 1000.0)
    }

    fn human_rtt(&self) -> String {
        match self.rtt {
            Some(d) => format!("{} ms", d.as_secs_f64() * 1000.0),
            None => String::new(),
        }
    }
}

async fn select_peer(
    identity: &account::Identity,
    protocol: Protocol,
    base_config: &str,
    wg_sessions: prober::WgSessionCache,
) -> Result<Selection> {
    let force_peer = match protocol {
        Protocol::Masque => runtime_env::var("AETHER_PEER"),
        Protocol::WireGuard | Protocol::WarpInWarp => {
            runtime_env::var("AETHER_WG_PEER").or_else(|| runtime_env::var("AETHER_PEER"))
        }
    };

    if let Some(p) = force_peer {
        let peer: SocketAddr = p
            .parse()
            .map_err(|_| AetherError::Other(format!("bad peer address {p}")))?;
        log::info!("[+] using forced peer {peer} (probe skipped)");
        // Nothing was measured, so the scan reports no RTT rather than a zero.
        return Ok(Selection { peer, rtt: None });
    }

    log::info!("[+] selected protocol: {}", protocol.label());
    session_event::set_phase(session_event::Phase::SelectingEndpoint);

    let mode_str = select_scan_mode_str().await;
    let ip = select_ip_version().await;

    match protocol {
        Protocol::Masque => {
            log::info!("[*] hunting for a working MASQUE gateway (deep connect-ip verification)");
            // Parsed once for the arm: both the probe and the cached-gateway
            // verification bind the same inner address, and a failure now stops the
            // session instead of handing both of them 172.16.0.2.
            let local_ipv4 = identity.tunnel_ipv4()?;
            let ech_config = resolve_ech().await;
            let mode = prober::ScanMode::parse(&mode_str);
            let probe = prober::MasqueProbe {
                sni: if masque_h2::enabled() {
                    consts::CONNECT_SNI.to_string()
                } else {
                    crate::quic::resolve_h3_sni()
                },
                authority: crate::quic::resolve_h3_authority(),
                path: crate::quic::resolve_h3_path(),
                cert_pem: std::sync::Arc::from(identity.cert_pem.clone()),
                key_pem: std::sync::Arc::from(identity.key_pem.clone()),
                ech_config_list: ech_config.clone().map(std::sync::Arc::from),
                noize: noize_config(),
                ports: prober::MASQUE_PORTS.to_vec(),
                ip,
                local_ipv4,
                config_path: base_config.to_string(),
            };

            // Smart reconnect: re-verify the last working gateway before paying
            // for a full scan. Skip with AETHER_QUICK_RECONNECT=0; force with =1.
            // Never quick-reconnect in scan-only (standalone scanner) mode: the
            // scanner must enumerate the whole pool and stream hits, not short-
            // circuit to one cached endpoint.
            if quick_reconnect_enabled() && !scan_only() {
                let cache_path = lastconn::cache_path(base_config);
                if let Some(cached) = lastconn::load(&cache_path) {
                    if let Ok(peer_addr) = cached.peer.parse::<SocketAddr>() {
                        log::info!("[*] verifying cached gateway {peer_addr} before reuse");
                        // Verify over the transport the tunnel will actually use.
                        // This call was always QUIC, so in H2 mode a gateway that
                        // answers on TCP 443 and never on UDP accumulated three
                        // strikes from its own health checks and was evicted —
                        // then every connect paid for a full scan again.
                        let verified = if masque_h2::enabled() {
                            let h2cfg = masque_h2::H2TunnelConfig {
                                peer: masque_h2::h2_peer(peer_addr),
                                sni: probe.sni.clone(),
                                authority: probe.authority.clone(),
                                cert_pem: identity.cert_pem.clone(),
                                key_pem: identity.key_pem.clone(),
                                probe_src: Some(local_ipv4),
                            };
                            masque_h2::verify_h2(&h2cfg, std::time::Duration::from_secs(6)).await
                        } else {
                            quick_verify_masque(
                                identity,
                                peer_addr,
                                &probe.sni,
                                ech_config.as_deref(),
                            )
                            .await
                        };
                        if let Ok(rtt) = verified {
                            log::info!("[+] cached gateway {peer_addr} still works; skipping scan");
                            if crate::cache::record_success(base_config, peer_addr, true)
                                .was_skipped()
                            {
                                log::warn!("[cache] quick-reconnect success for {peer_addr} was not recorded");
                            }
                            session_event::emit(SessionEvent::EndpointSelected {
                                addr: peer_addr.to_string(),
                                protocol: "masque".into(),
                                rtt_ms: Some(rtt.as_secs_f64() * 1000.0),
                            });
                            return Ok(Selection {
                                peer: peer_addr,
                                rtt: Some(rtt),
                            });
                        } else {
                            log::warn!(
                                "[-] cached gateway {peer_addr} no longer works; scanning fresh"
                            );
                            // Evict the dead peer from the trust cache so we stop
                            // trying it first on every reconnect after a network change.
                            if crate::cache::record_failure(base_config, peer_addr, true)
                                .was_skipped()
                            {
                                log::warn!("[cache] quick-reconnect failure for {peer_addr} was not recorded");
                            }
                        }
                    }
                }
            }

            let best = prober::hunt_best_gateway(&probe, mode).await?;
            log::info!(
                "[+] selected MASQUE gateway {}:{} (rtt {:?})",
                best.ip,
                best.port,
                best.rtt
            );
            let peer = SocketAddr::new(best.ip, best.port);
            // Cache the working gateway so the next session can quick-reconnect.
            lastconn::save(&lastconn::cache_path(base_config), &peer.to_string(), "");
            session_event::emit(SessionEvent::EndpointSelected {
                addr: format!("{}:{}", best.ip, best.port),
                protocol: "masque".into(),
                rtt_ms: Some(best.rtt.as_secs_f64() * 1000.0),
            });
            Ok(Selection {
                peer,
                rtt: Some(best.rtt),
            })
        }
        Protocol::WireGuard | Protocol::WarpInWarp => {
            log::info!(
                "[*] hunting for a working WireGuard endpoint (handshake + data-plane verification)"
            );
            let mode = prober::ScanMode::parse(&mode_str);

            let private_key = identity.private_key_bytes()?;
            let peer_public = identity.peer_public_key_bytes()?;

            let probe = prober::WgProbe {
                private_key: std::sync::Arc::new(private_key),
                peer_public_key: std::sync::Arc::new(peer_public),
                client_id: identity.client_id,
                local_ipv4: identity.tunnel_ipv4()?,
                aethernoize: aethernoize_config(),
                ports: wireguard::WG_PORTS.to_vec(),
                ip,
                config_path: base_config.to_string(),
                sessions: wg_sessions,
            };

            let best = prober::hunt_best_wg_endpoint(&probe, mode).await?;
            log::info!(
                "[+] selected WireGuard endpoint {}:{} (rtt {:?})",
                best.ip,
                best.port,
                best.rtt
            );
            Ok(Selection {
                peer: SocketAddr::new(best.ip, best.port),
                rtt: Some(best.rtt),
            })
        }
    }
}

/// Smart reconnect gating. Defaults ON (column requested); turn off via
/// AETHER_QUICK_RECONNECT=0/false/no/off, force-on via =1/true/yes/on. Forcing
/// only matters when nothing is cached (in which case there is nothing to
/// verify anyway, so force-on is effectively the same as default here).
fn quick_reconnect_enabled() -> bool {
    match crate::runtime_env::var("AETHER_QUICK_RECONNECT") {
        // Same truth table as every other boolean knob: `0/false/no/off` mean
        // off, anything unrecognised falls back to the default-on behaviour.
        Some(v) if !v.trim().is_empty() => crate::runtime_env::truthy(&v),
        _ => true, // default: attempt cached-gateway reuse when present
    }
}

/// Quick gate verify for smart reconnect: re-runs the same deep CONNECT-IP +
/// data-plane proof path the scanner uses, but on a single cached endpoint
/// with a tight timeout. Returns Ok(rtt) when the cached gateway is still
/// serving live traffic, Err otherwise.
async fn quick_verify_masque(
    identity: &account::Identity,
    peer: SocketAddr,
    sni: &str,
    ech: Option<&[u8]>,
) -> Result<std::time::Duration> {
    let local_ipv4 = identity.tunnel_ipv4()?;

    let vp = quic::VerifyParams {
        peer,
        sni: sni.to_string(),
        authority: crate::quic::resolve_h3_authority(),
        path: crate::quic::resolve_h3_path(),
        cert_pem: identity.cert_pem.clone(),
        key_pem: identity.key_pem.clone(),
        ech_config_list: ech.map(|b| b.to_vec()),
        noize: noize_config(),
        timeout: std::time::Duration::from_secs(6),
        local_ipv4,
        header_mode: crate::masque::H3HeaderMode::Standard,
        protocol: None,
    };
    quic::verify_masque(&vp).await
}

/// Does this failure say something about ECH, as opposed to "the connect did not
/// work"?
///
/// The whole point of the distinction: an unrelated failure (blocked UDP, a dead
/// gateway, an expired pin) used to take the same path as an ECH problem and strip
/// ECH from the retry. Token comparison rather than a substring test because
/// "reachable" and "which" both contain the letters.
fn ech_related(err: &AetherError) -> bool {
    if matches!(err, AetherError::Ech(_)) {
        return true;
    }
    err.to_string()
        .to_ascii_lowercase()
        .split(|c: char| !c.is_ascii_alphanumeric())
        .any(|tok| {
            matches!(
                tok,
                "ech" | "echconfig" | "echconfiglist" | "encrypted_client_hello"
            )
        })
}

async fn resolve_ech() -> Option<Vec<u8>> {
    match crate::runtime_env::var("AETHER_ECH") {
        Some(v)
            if v == "0" || v.eq_ignore_ascii_case("off") || v.eq_ignore_ascii_case("disable") =>
        {
            log::info!("[+] ECH explicitly disabled via AETHER_ECH={v}");
            None
        }
        Some(v) if v.eq_ignore_ascii_case("auto") => match dns::fetch_ech_config().await {
            Ok(raw) => {
                log::info!(
                    "[+] fetched ECHConfigList automatically ({} bytes)",
                    raw.len()
                );
                Some(raw)
            }
            Err(e) => {
                log::warn!("[-] ECH auto-fetch failed ({e}); continuing without ECH");
                None
            }
        },
        Some(b64) if !b64.is_empty() => match tls::decode_ech_config_list(&b64) {
            Ok(v) => {
                log::info!("[+] using ECHConfigList from AETHER_ECH");
                Some(v)
            }
            Err(e) => {
                log::warn!("[-] bad AETHER_ECH: {e}; continuing without ECH");
                None
            }
        },
        _ => {
            // Default: OFF. Auto-fetching an ECHConfigList and injecting it into the
            // QUIC ClientHello can trip a BoringSSL assertion in
            // encrypted_client_hello.cc and abort() the whole process mid-handshake
            // (observed on H3). ECH only encrypts the SNI (already the expected
            // consumer-masque name to Cloudflare), so a hard crash is never worth it.
            // Opt in with AETHER_ECH=auto or a base64 ECHConfigList.
            log::info!("[+] ECH off by default (set AETHER_ECH=auto to encrypt SNI)");
            None
        }
    }
}

// ─── MASQUE tunnel runner ───────────────────────────────────────────────────

async fn run_masque_tunnel(
    identity: account::Identity,
    peer: SocketAddr,
    ech: Option<Vec<u8>>,
    listen: SocketAddr,
    http_listen: SocketAddr,
) -> Result<()> {
    let mtu_val = mtu::resolve_mtu("masque", !identity.ipv6.trim().is_empty()).await;
    // H3 CONNECT-IP carries inner IP packets as QUIC DATAGRAMs, whose size is bounded
    // by the QUIC path MTU minus framing. A higher netstack MTU silently drops full-size
    // TCP packets (tunnel_ready yet curl times out). Cap the H3 data-plane MTU so inner
    // packets always fit the datagram; H2 (capsules over the stream) is unaffected.
    // Threaded explicitly into the netstack/TUN spawn below instead of a global
    // AETHER_MTU set() that a concurrent scan/tunnel in the same process could clobber.
    let stack_mtu = if masque_h2::enabled() {
        mtu_val
    } else {
        let capped = mtu_val.min(1280);
        if capped != mtu_val {
            log::info!(
                "[+] H3 data-plane MTU capped to {capped} (was {mtu_val}) to fit QUIC DATAGRAM"
            );
        }
        capped
    };
    let (chans, internals) = quic::channels();
    // The inner address the tunnel is bound to, parsed once: the config below and
    // the H2 probe source are the same value, and neither used to be able to say
    // "the identity I was handed has no readable tunnel address".
    let local_ipv4 = identity.tunnel_ipv4()?;

    let cfg = quic::TunnelConfig {
        peer,
        sni: if masque_h2::enabled() {
            consts::CONNECT_SNI.to_string()
        } else {
            crate::quic::resolve_h3_sni()
        },
        authority: crate::quic::resolve_h3_authority(),
        path: crate::quic::resolve_h3_path(),
        cert_pem: identity.cert_pem.clone(),
        key_pem: identity.key_pem.clone(),
        local_ipv4,
        ech_config_list: ech,
        noize: noize_config(),
    };

    let quic::Channels {
        outbound_tx,
        inbound_rx,
    } = chans;

    let route_peer = if masque_h2::enabled() {
        masque_h2::h2_peer(peer)
    } else {
        peer
    };
    let (stack, _tun) = spawn_stack_and_optional_tun(
        &identity.ipv4,
        &identity.ipv6,
        route_peer,
        stack_mtu,
        inbound_rx,
        outbound_tx,
    )
    .await?;

    let (addr_tx, mut addr_rx) = tokio::sync::mpsc::channel::<quic::AssignedAddr>(64);
    if let Some(bridge_stack) = stack.clone() {
        tokio::spawn(async move {
            while let Some(a) = addr_rx.recv().await {
                let res = match a.ip {
                    IpAddr::V4(v4) => bridge_stack.set_addrs(Some((v4, a.prefix)), None).await,
                    IpAddr::V6(v6) => bridge_stack.set_addrs(None, Some((v6, a.prefix))).await,
                };
                if let Err(e) = res {
                    log::warn!("[-] failed to sync edge address into netstack: {e}");
                }
            }
        });
    } else {
        // CONNECT-IP may send repeated address capsules. Drain them in TUN mode
        // so the bounded control channel can never stall the transport task.
        tokio::spawn(async move { while addr_rx.recv().await.is_some() {} });
    }

    // Proxy services are intentionally disabled in full-device TUN mode: sharing
    // one tunnel identity between Windows TCP/IP and smoltcp corrupts flow ownership.
    let (mut socks_task, mut http_task) = if let Some(stack) = stack.clone() {
        let socks_listener = socks::bind(listen).await?;
        let http_listener = http_proxy::bind(http_listen).await?;
        let socks_stack = stack.clone();
        let socks_task = tokio::spawn(async move {
            log::info!("[+] socks5 server listening on {listen}");
            socks::serve_listener(socks_listener, socks_stack).await
        });
        let http_task = tokio::spawn(http_proxy::serve_listener(http_listener, stack));
        (Some(socks_task), Some(http_task))
    } else {
        (None, None)
    };

    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel::<()>();
    // H3 gets its data-plane probe source from TunnelConfig.local_ipv4; H2 takes it
    // as a param below. No process-global AETHER_PROBE_SRC clobber between a scan
    // and a tunnel that share one process.
    let probe_src = Some(local_ipv4);

    let tunnel_handle = if masque_h2::enabled() {
        let h2cfg = masque_h2::H2TunnelConfig {
            peer: masque_h2::h2_peer(peer),
            sni: consts::CONNECT_SNI.to_string(),
            authority: quic::default_authority().to_string(),
            cert_pem: identity.cert_pem.clone(),
            key_pem: identity.key_pem.clone(),
            probe_src,
        };
        log::info!("[+] MASQUE transport: HTTP/2 (TCP) to {}", h2cfg.peer);
        let _ = &cfg;
        tokio::spawn(async move { masque_h2::run(h2cfg, internals, Some(addr_tx), ready_tx).await })
    } else {
        log::info!("[+] MASQUE transport: HTTP/3 (QUIC) to {}", peer);
        tokio::spawn(async move { quic::run(cfg, internals, Some(addr_tx), ready_tx).await })
    };

    match tokio::time::timeout(Duration::from_secs(20), ready_rx).await {
        Ok(Ok(())) => {
            if stack.is_some() {
                session_event::emit(SessionEvent::ProxyReady {
                    socks: listen.to_string(),
                    http: http_listen.to_string(),
                });
            }
            // The only place the MASQUE tunnel is actually up. `Phase::Tunnel` had
            // no assignment anywhere, so the phase the pulse reported could not be
            // "carrying traffic" — and the supervision loop below, which is where
            // a connected session spends the rest of its life, was unlabelled.
            session_event::set_phase(session_event::Phase::Tunnel);
            session_event::emit(SessionEvent::TunnelReady {
                transport: if masque_h2::enabled() {
                    "masque-h2".into()
                } else {
                    "masque-h3".into()
                },
            });
            session_event::emit(SessionEvent::Connected {
                detail: if stack.is_some() {
                    "masque proxies ready".into()
                } else {
                    "masque full-device tunnel ready".into()
                },
            });
        }
        Ok(Err(_)) => {
            tunnel_handle.abort();
            if let Some(task) = socks_task.take() {
                task.abort();
                let _ = task.await;
            }
            if let Some(task) = http_task.take() {
                task.abort();
                let _ = task.await;
            }
            return Err(AetherError::Other(
                "MASQUE data-plane did not come up (the network may be blocking QUIC/UDP; try HTTP/2 or WireGuard)".into(),
            ));
        }
        Err(_) => {
            tunnel_handle.abort();
            if let Some(task) = socks_task.take() {
                task.abort();
                let _ = task.await;
            }
            if let Some(task) = http_task.take() {
                task.abort();
                let _ = task.await;
            }
            return Err(AetherError::Other(
                "timed out waiting for MASQUE data-plane (the network may be blocking QUIC/UDP; try HTTP/2 or WireGuard)".into(),
            ));
        }
    }

    // Supervise the tunnel AND the proxy servers together. If the tunnel task dies
    // (peer dropped, transport error) OR a proxy listener exits, tear the rest down
    // and return so the caller's reconnect loop regains control. Awaiting only the
    // tunnel (as before) let a dead SOCKS listener sit undetected behind a live
    // tunnel, and vice-versa — the "connected but no traffic" silent hang.
    //
    // The interval arm is the session's heartbeat anchor. `session_event`'s pulse
    // is gated on progress, so this loop — the one place the tunnel phase spends
    // its life — has to say "I am still here and my transport task has not exited"
    // or a healthy tunnel would look stalled.
    let mut tunnel_handle = tunnel_handle;
    let mut supervise = tokio::time::interval(SUPERVISE_TICK);
    let tunnel_result: Result<()> = loop {
        tokio::select! {
            r = &mut tunnel_handle => break match r {
                Ok(inner) => inner,
                Err(e) => Err(AetherError::Other(format!("tunnel task: {e}"))),
            },
            _ = await_opt(&mut socks_task) => break Err(AetherError::Other("socks5 server exited".into())),
            _ = await_opt(&mut http_task) => break Err(AetherError::Other("http proxy exited".into())),
            _ = supervise.tick().await => session_event::mark_progress(),
        }
    };

    // Tear everything down. abort() on the tunnel is a no-op if it already ended.
    // The proxy tasks are aborted AND awaited so their listen sockets are fully
    // released before a reconnect rebinds the same ports ("Address already in use"
    // fix). await_opt clears whichever handle already completed, so we never
    // re-await a finished task here.
    tunnel_handle.abort();
    if let Some(task) = socks_task.take() {
        task.abort();
        let _ = task.await;
    }
    if let Some(task) = http_task.take() {
        task.abort();
        let _ = task.await;
    }

    match tunnel_result {
        Ok(()) => Ok(()),
        Err(e) => Err(AetherError::Other(format!("tunnel exited: {e}"))),
    }
}

/// Await an optional task handle to completion (clearing it so it is not awaited
/// twice), or pend forever when the task is absent — e.g. the proxies are disabled
/// in full-device TUN mode. Lets one `select!` arm watch a proxy that may not exist.
async fn await_opt<T>(handle: &mut Option<tokio::task::JoinHandle<T>>) {
    if let Some(h) = handle.as_mut() {
        let _ = h.await;
    } else {
        std::future::pending::<()>().await;
        return;
    }
    *handle = None;
}

// ─── WireGuard tunnel runner ────────────────────────────────────────────────

/// The single definition lives in `wireguard.rs`, beside the probe that has to
/// use the same value — see `wireguard::persistent_keepalive_secs`.
fn wg_keepalive_secs() -> u16 {
    crate::wireguard::persistent_keepalive_secs()
}

async fn run_wireguard(
    identity: account::Identity,
    listen: SocketAddr,
    http_listen: SocketAddr,
    base_config: &str,
) -> Result<()> {
    let forced = runtime_env::var("AETHER_WG_PEER").or_else(|| runtime_env::var("AETHER_PEER"));

    let private_key = identity.private_key_bytes()?;
    let peer_public = identity.peer_public_key_bytes()?;
    let ipv4 = identity.tunnel_ipv4()?;

    let primary_profile =
        runtime_env::var("AETHER_NOIZE").unwrap_or_else(|| "balanced".to_string());
    let profile = obfuscation::aethernoize_from_name(&primary_profile);

    let wg_sessions = prober::WgSessionCache::new();

    let peer = if let Some(p) = forced {
        let p_addr: SocketAddr = p
            .parse()
            .map_err(|_| AetherError::Other(format!("bad peer address {p}")))?;
        log::info!("[+] using forced peer {p_addr} (probe skipped)");
        p_addr
    } else {
        let mode_str = select_scan_mode_str().await;
        let ip = select_ip_version().await;
        let mode = prober::ScanMode::parse(&mode_str);

        log::info!(
            "[*] hunting for a working WireGuard endpoint (mode={}, aethernoize='{}')",
            mode.label(),
            primary_profile
        );

        let probe = prober::WgProbe {
            private_key: std::sync::Arc::new(private_key),
            peer_public_key: std::sync::Arc::new(peer_public),
            client_id: identity.client_id,
            local_ipv4: ipv4,
            aethernoize: profile.clone(),
            ports: wireguard::WG_PORTS.to_vec(),
            ip,
            config_path: base_config.to_string(),
            sessions: wg_sessions.clone(),
        };

        let best = prober::hunt_best_wg_endpoint(&probe, mode).await?;
        log::info!(
            "[+] selected WireGuard endpoint {}:{} (rtt {:?})",
            best.ip,
            best.port,
            best.rtt
        );
        SocketAddr::new(best.ip, best.port)
    };

    log::info!("[+] using cloudflare edge {peer}");
    session_event::emit(SessionEvent::EndpointSelected {
        addr: peer.to_string(),
        protocol: "wireguard".into(),
        rtt_ms: None,
    });
    // M2 fix: reuse the handshake the scanner already established for this peer
    // instead of performing a second one (Cloudflare edges punish double
    // handshakes — see the comment in run_wireguard_tunnel).
    let established = wg_sessions.take(&peer);
    run_wireguard_tunnel(identity, peer, profile, listen, http_listen, established).await
}

async fn run_wireguard_tunnel(
    identity: account::Identity,
    peer: SocketAddr,
    aethernoize: aethernoize::AetherNoizeConfig,
    listen: SocketAddr,
    http_listen: SocketAddr,
    established: Option<wireguard::EstablishedSession>,
) -> Result<()> {
    // Critical: do NOT open a separate verify session then a second Tunn.
    // Cloudflare edges rate-limit / confuse double handshakes; the old path
    // left SOCKS up on a fresh unestablished tunnel → CONNECT hangs forever.
    let private_key = identity.private_key_bytes()?;
    let peer_public = identity.peer_public_key_bytes()?;
    let mtu = wireguard_mtu(!identity.ipv6.trim().is_empty()).await;
    log::info!("[+] using MTU={mtu} for wireguard session");

    let cfg = wireguard::WgConfig {
        local_private_key: private_key,
        peer_public_key: peer_public,
        peer_endpoint: peer,
        client_id: identity.client_id,
        persistent_keepalive: Some(wg_keepalive_secs()),
        aethernoize: std::sync::Arc::new(aethernoize.clone()),
    };

    let (tchans, tints) = tunnel::channels();
    let wg_tunnel = if let Some(session) = established {
        log::info!("[+] reusing scan-verified WireGuard session (no second handshake)");
        wireguard::WgTunnel::from_established(
            session,
            std::sync::Arc::new(aethernoize),
            tints.inbound_tx,
        )
    } else {
        wireguard::WgTunnel::new(cfg, tints.inbound_tx).await?
    };

    session_event::emit(SessionEvent::TunnelReady {
        transport: "wireguard".into(),
    });

    // Only open proxies after the session is established so the first TCP SYN
    // is encapsulated under a ready tunnel (not dropped as handshake-only).
    let (stack, _tun) = spawn_stack_and_optional_tun(
        &identity.ipv4,
        &identity.ipv6,
        peer,
        mtu,
        tchans.inbound_rx,
        tchans.outbound_tx,
    )
    .await?;

    let (mut socks_task, mut http_task) = if let Some(stack) = stack {
        let socks_listener = socks::bind(listen).await?;
        let http_listener = http_proxy::bind(http_listen).await?;
        let socks_stack = stack.clone();
        let socks_task = tokio::spawn(async move {
            log::info!("[+] socks5 server listening on {listen}");
            socks::serve_listener(socks_listener, socks_stack).await
        });
        let http_task = tokio::spawn(http_proxy::serve_listener(http_listener, stack));
        session_event::emit(SessionEvent::ProxyReady {
            socks: listen.to_string(),
            http: http_listen.to_string(),
        });
        (Some(socks_task), Some(http_task))
    } else {
        (None, None)
    };
    session_event::set_phase(session_event::Phase::Tunnel);
    session_event::emit(SessionEvent::Connected {
        detail: if socks_task.is_some() {
            "wireguard proxies up".into()
        } else {
            "wireguard full-device tunnel ready".into()
        },
    });

    // Supervised exactly like the MASQUE path: the tunnel and both proxy listeners
    // are awaited together, and whichever of them finishes first ends the session.
    // Awaiting only the tunnel meant a dead SOCKS or HTTP listener went unnoticed
    // behind a live WireGuard session, and its socket was never confirmed released
    // before the next connect rebound the same port — the "Address already in use"
    // reconnect failure. The interval arm is the progress the heartbeat needs.
    let mut tunnel_fut = std::pin::pin!(wg_tunnel.run(tints.outbound_rx));
    let mut supervise = tokio::time::interval(SUPERVISE_TICK);
    let tunnel_result = loop {
        tokio::select! {
            r = &mut tunnel_fut => break r,
            _ = await_opt(&mut socks_task) => break Err(AetherError::Other("socks5 server exited".into())),
            _ = await_opt(&mut http_task) => break Err(AetherError::Other("http proxy exited".into())),
            _ = supervise.tick().await => session_event::mark_progress(),
        }
    };

    // Drop the tunnel future first (it owns the socket), then abort AND await the
    // proxies so their listen sockets are gone before a reconnect rebinds.
    drop(tunnel_fut);
    if let Some(task) = socks_task.take() {
        task.abort();
        let _ = task.await;
    }
    if let Some(task) = http_task.take() {
        task.abort();
        let _ = task.await;
    }

    match tunnel_result {
        Ok(()) => Ok(()),
        Err(e) => Err(AetherError::Other(format!("wireguard tunnel exited: {e}"))),
    }
}

// ─── WARP-in-WARP (gool) tunnel runner ─────────────────────────────────────

async fn spawn_stack_and_optional_tun(
    ipv4: &str,
    ipv6: &str,
    peer: SocketAddr,
    mtu: usize,
    inbound_rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
    outbound_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
) -> Result<(
    Option<netstack::StackHandle>,
    Option<routing_plane::TunGuard>,
)> {
    routing_plane::spawn(ipv4, ipv6, peer, mtu, inbound_rx, outbound_tx).await
}

async fn establish_wg(
    identity: &account::Identity,
    peer: SocketAddr,
    mtu: usize,
    obfuscate: bool,
    keepalive: u16,
    label: &'static str,
) -> Result<(netstack::StackHandle, AbortOnDrop<()>)> {
    let private_key = identity.private_key_bytes()?;
    let peer_public = identity.peer_public_key_bytes()?;

    let profile = if obfuscate {
        aethernoize_config()
    } else {
        aethernoize::from_profile("off")
    };

    let cfg = wireguard::WgConfig {
        local_private_key: private_key,
        peer_public_key: peer_public,
        peer_endpoint: peer,
        client_id: identity.client_id,
        persistent_keepalive: Some(keepalive),
        aethernoize: std::sync::Arc::new(profile),
    };

    let (outbound_tx, outbound_rx) = tokio::sync::mpsc::channel(crate::tunnel::NET_QUEUE);
    let (inbound_tx, inbound_rx) = tokio::sync::mpsc::channel(crate::tunnel::NET_QUEUE);

    let wg_tunnel = wireguard::WgTunnel::new(cfg, inbound_tx).await?;

    let stack = netstack::spawn(&identity.ipv4, &identity.ipv6, mtu, inbound_rx, outbound_tx)?;

    // M12 fix: the tunnel task used to be spawned detached, so a failed inner
    // establishment leaked the OUTER tunnel — still handshaking/pinging the edge
    // — on every retry. The AbortOnDrop guard ties its lifetime to the caller.
    let handle = tokio::spawn(async move {
        if let Err(e) = wg_tunnel.run(outbound_rx).await {
            log::error!("[{label}] wireguard tunnel exited: {e}");
        }
    });

    Ok((stack, AbortOnDrop(handle)))
}

struct UdpForwarderGuard {
    // Fields exist purely for their Drop side effects (abort on teardown).
    #[allow(dead_code)]
    up: AbortOnDrop<()>,
    #[allow(dead_code)]
    down: AbortOnDrop<()>,
}

async fn spawn_udp_forwarder(
    outer: &netstack::StackHandle,
    remote: SocketAddr,
) -> Result<(SocketAddr, UdpForwarderGuard)> {
    let sock = std::sync::Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await?);
    let local = sock.local_addr()?;

    let udp = outer.open_udp().await?;
    let (udp_tx, mut udp_rx) = udp.into_split();

    let inner_peer: std::sync::Arc<tokio::sync::Mutex<Option<SocketAddr>>> =
        std::sync::Arc::new(tokio::sync::Mutex::new(None));

    let up_sock = sock.clone();
    let up_peer = inner_peer.clone();
    let up_task = tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        while let Ok((n, from)) = up_sock.recv_from(&mut buf).await {
            *up_peer.lock().await = Some(from);
            if udp_tx.send_to(remote, buf[..n].to_vec()).await.is_err() {
                break;
            }
        }
    });

    let down_sock = sock.clone();
    let down_peer = inner_peer.clone();
    let down_task = tokio::spawn(async move {
        while let Some((_src, data)) = udp_rx.recv().await {
            let dst = *down_peer.lock().await;
            if let Some(dst) = dst {
                let _ = down_sock.send_to(&data, dst).await;
            }
        }
    });

    Ok((
        local,
        UdpForwarderGuard {
            up: AbortOnDrop(up_task),
            down: AbortOnDrop(down_task),
        },
    ))
}

async fn run_warp_in_warp(
    primary: account::Identity,
    secondary: account::Identity,
    peer: SocketAddr,
    listen: SocketAddr,
    http_listen: SocketAddr,
) -> Result<()> {
    let outer_mtu = wireguard_mtu(!primary.ipv6.trim().is_empty()).await;
    log::info!("[*] establishing outer WARP tunnel to {peer}...");
    let (outer_stack, mut outer_task) =
        establish_wg(&primary, peer, outer_mtu, true, 5, "outer").await?;

    // M12 fix: active data-plane gate instead of a fixed 1.5s hope-the-handshake-
    // finished sleep. Slow links used to start the inner tunnel against an outer
    // path that was still handshaking.
    wait_stack_alive(&outer_stack, "outer WARP").await?;

    let (forwarder, _forwarder_guard) = spawn_udp_forwarder(&outer_stack, peer).await?;
    log::info!("[+] inner endpoint tunneled through outer warp via {forwarder}");

    log::info!("[*] establishing inner WARP tunnel (warp-in-warp)...");
    let inner_mtu = inner_mtu_for(outer_mtu);
    let (inner_stack, mut inner_task) =
        establish_wg(&secondary, forwarder, inner_mtu, false, 20, "inner").await?;
    // Same gate for the inner leg before proxies accept traffic.
    wait_stack_alive(&inner_stack, "inner WARP").await?;

    let socks_listener = socks::bind(listen).await?;
    let http_listener = http_proxy::bind(http_listen).await?;
    log::info!("[+] socks5 server listening on {listen}");
    let http_task = tokio::spawn(http_proxy::serve_listener(
        http_listener,
        inner_stack.clone(),
    ));
    session_event::emit(SessionEvent::ProxyReady {
        socks: listen.to_string(),
        http: http_listen.to_string(),
    });
    session_event::emit(SessionEvent::TunnelReady {
        transport: "gool".into(),
    });
    session_event::set_phase(session_event::Phase::Tunnel);
    session_event::emit(SessionEvent::Connected {
        detail: "warp-in-warp ready".into(),
    });

    // Both WARP legs are supervised alongside the two proxy listeners, like the
    // MASQUE path. Previously only the SOCKS listener was awaited: an outer or
    // inner tunnel that died logged its error from inside its own task and left
    // the proxies accepting connections that nothing would ever answer, and the
    // HTTP task was aborted without being awaited so its port could still be held
    // when the next connect rebound it.
    let mut http_task = Some(http_task);
    let mut socks_fut = std::pin::pin!(socks::serve_listener(socks_listener, inner_stack));
    let mut supervise = tokio::time::interval(SUPERVISE_TICK);
    let result = loop {
        tokio::select! {
            r = &mut socks_fut => break r,
            _ = outer_task.done() => break Err(AetherError::Other("outer WARP tunnel exited".into())),
            _ = inner_task.done() => break Err(AetherError::Other("inner WARP tunnel exited".into())),
            _ = await_opt(&mut http_task) => break Err(AetherError::Other("http proxy exited".into())),
            _ = supervise.tick().await => session_event::mark_progress(),
        }
    };
    drop(socks_fut);
    if let Some(task) = http_task.take() {
        task.abort();
        let _ = task.await;
    }
    result
}

// ─── Interactive prompts ────────────────────────────────────────────────────

async fn prompt_line(prompt: &str) -> Option<String> {
    use std::io::IsTerminal;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    if !std::io::stdin().is_terminal() {
        return None;
    }

    let mut stdout = tokio::io::stdout();
    let _ = stdout.write_all(prompt.as_bytes()).await;
    let _ = stdout.flush().await;

    let mut line = String::new();
    let mut reader = BufReader::new(tokio::io::stdin());
    match reader.read_line(&mut line).await {
        Ok(0) | Err(_) => None,
        Ok(_) => Some(line.trim().to_string()),
    }
}

const SCAN_MODE_PROMPT: &str = "\nScan mode:\n  [1] turbo     (fast, first hit)\n  [2] balanced  (default)\n  [3] thorough  (deep, best ping)\n  [4] stealth   (quiet, patient)\n  [5] ironclad  (real tunnel + real HTTP check per candidate, guaranteed working)\nChoose [1-5] (default 2): ";

async fn select_scan_mode_str() -> String {
    if let Some(v) = runtime_env::var("AETHER_SCAN") {
        return v;
    }

    let answer = prompt_line(SCAN_MODE_PROMPT).await;

    match answer.as_deref() {
        Some("1") => "turbo".to_string(),
        Some("3") => "thorough".to_string(),
        Some("4") => "stealth".to_string(),
        Some("5") => "ironclad".to_string(),
        _ => "balanced".to_string(),
    }
}

async fn select_protocol() -> Protocol {
    if let Some(v) = crate::runtime_env::var("AETHER_PROTOCOL") {
        return Protocol::parse(&v);
    }

    let answer = prompt_line(
        "\nProtocol:\n  [1] MASQUE (modern, QUIC/H3, default)\n  [2] WireGuard (classic, faster)\n  [3] WARP-in-WARP / gool\nChoose [1-3] (default 1): ",
    )
    .await;

    match answer.as_deref() {
        Some("2") => Protocol::WireGuard,
        Some("3") => Protocol::WarpInWarp,
        _ => Protocol::Masque,
    }
}

async fn select_ip_version() -> prober::IpScan {
    if let Some(v) = runtime_env::var("AETHER_IP") {
        return prober::IpScan::parse(&v);
    }

    let answer = prompt_line(
        "\nIP version to scan:\n  [1] IPv4 (default)\n  [2] IPv6\n  [3] Both\nChoose [1-3] (default 1): ",
    )
    .await;

    match answer.as_deref() {
        Some("2") => prober::IpScan::V6,
        Some("3") => prober::IpScan::Both,
        _ => prober::IpScan::V4,
    }
}
