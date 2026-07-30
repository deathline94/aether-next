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

fn tunnel_mtu() -> usize {
    mtu::current()
}

fn inner_mtu() -> usize {
    tunnel_mtu().saturating_sub(120).max(1200)
}

// ─── Protocol ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Masque,
    WireGuard,
    WarpInWarp,
}

impl Protocol {
    pub fn parse(s: &str) -> Protocol {
        match s.trim().to_lowercase().as_str() {
            "wg" | "wireguard" => Protocol::WireGuard,
            "gool" | "wiw" | "warp-in-warp" | "warpinwarp" => Protocol::WarpInWarp,
            _ => Protocol::Masque,
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

    let protocol = if cfg.has_forced_peer() || std::env::var("AETHER_PROTOCOL").is_ok() {
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
            let peer = match select_peer(&identity, protocol, &base_config).await {
                Ok(p) => p,
                Err(e) if !masque_h2::enabled() => {
                    let ep = identity
                        .masque_endpoint
                        .clone()
                        .unwrap_or_else(|| consts::MASQUE_H3_ENDPOINT.to_string());
                    match ep.parse::<SocketAddr>() {
                        Ok(a) => {
                            log::warn!(
                                "[-] MASQUE H3 scan found no endpoint ({e}); falling back to {a}"
                            );
                            a
                        }
                        Err(_) => return Err(e),
                    }
                }
                Err(e) => return Err(e),
            };
            log::info!("[+] using cloudflare edge {peer}");
            session_event::emit(SessionEvent::EndpointSelected {
                addr: peer.to_string(),
                protocol: "masque".into(),
            });
            // Scan-only mode: report result and exit without tunnel.
            if scan_only() {
                session_event::emit(SessionEvent::ScanDone {
                    addr: peer.to_string(),
                    rtt: String::new(),
                    protocol: "masque".into(),
                });
                return Ok(());
            }
            let ech = resolve_ech().await;
            let result = run_masque_tunnel(identity.clone(), peer, ech.clone(), listen, http_listen).await;
            // ECH fallback: if the tunnel failed and ECH was active, the network
            // may be blocking ECH ClientHellos. Retry once without ECH.
            let result = if result.is_err() && ech.is_some() {
                log::warn!("[-] tunnel failed with ECH active; retrying without ECH (network may block ECH)");
                run_masque_tunnel(identity, peer, None, listen, http_listen).await
            } else {
                result
            };
            // Feed the real connect outcome into the trust cache so endpoint
            // ranking learns from actual connections, not just scan reachability.
            if result.is_ok() {
                crate::cache::record_success(&base_config, peer, true);
            } else {
                crate::cache::record_failure(&base_config, peer, true);
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
            // Scan-only mode: select peer then report.
            if scan_only() {
                let peer = select_peer(&identity, protocol, &base_config).await?;
                session_event::emit(SessionEvent::ScanDone {
                    addr: peer.to_string(),
                    rtt: String::new(),
                    protocol: "wireguard".into(),
                });
                return Ok(());
            }
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
            let peer = select_peer(&primary, Protocol::WireGuard, &base_config).await?;
            log::info!("[+] using cloudflare edge {peer} (outer)");
            session_event::emit(SessionEvent::EndpointSelected {
                addr: peer.to_string(),
                protocol: "gool".into(),
            });
            if scan_only() {
                session_event::emit(SessionEvent::ScanDone {
                    addr: peer.to_string(),
                    rtt: String::new(),
                    protocol: "gool".into(),
                });
                return Ok(());
            }
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
    if let Ok(p) = std::env::var("AETHER_WG_CONFIG") {
        return p;
    }
    base.to_string()
}

fn masque_config_path(base: &str) -> String {
    if let Ok(p) = std::env::var("AETHER_MASQUE_CONFIG") {
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
    let _provision = crate::cache::provision_lock(config_path);
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
    let _provision = crate::cache::provision_lock(config_path);

    // Re-check after acquiring the lock: another process may have just finished.
    if let Some(identity) = config::load(config_path)? {
        if identity.can_run_masque() {
            log::info!("[+] masque identity ready (provisioned by a concurrent process); reusing");
            return Ok(identity);
        }
        log::info!("[+] masque identity missing credentials; enrolling masque key");
        let (cert_pem, key_pem, masque_endpoint) = account::ensure_masque_enrolled(&identity).await?;
        let identity = account::Identity {
            cert_pem,
            key_pem,
            masque_endpoint,
            ..identity
        };
        config::save(config_path, &identity)?;
        return Ok(identity);
    }

    log::info!("[+] no masque identity found; provisioning dedicated masque account");
    let identity =
        account::provision_wg(consts::DEFAULT_MODEL, consts::DEFAULT_LOCALE, None).await?;
    let (cert_pem, key_pem, masque_endpoint) = account::ensure_masque_enrolled(&identity).await?;
    let identity = account::Identity {
        cert_pem,
        key_pem,
        masque_endpoint,
        ..identity
    };
    config::save(config_path, &identity)?;
    log::info!("[+] provisioned and saved new masque identity to {config_path}");
    Ok(identity)
}

// ─── Endpoint selection ─────────────────────────────────────────────────────

async fn select_peer(
    identity: &account::Identity,
    protocol: Protocol,
    base_config: &str,
) -> Result<SocketAddr> {
    let force_peer = match protocol {
        Protocol::Masque => std::env::var("AETHER_PEER").ok(),
        Protocol::WireGuard | Protocol::WarpInWarp => std::env::var("AETHER_WG_PEER")
            .ok()
            .or_else(|| std::env::var("AETHER_PEER").ok()),
    };

    if let Some(p) = force_peer {
        let peer: SocketAddr = p
            .parse()
            .map_err(|_| AetherError::Other(format!("bad peer address {p}")))?;
        log::info!("[+] using forced peer {peer} (probe skipped)");
        return Ok(peer);
    }

    log::info!("[+] selected protocol: {}", protocol.label());

    let mode_str = select_scan_mode_str().await;
    let ip = select_ip_version().await;

    match protocol {
        Protocol::Masque => {
            log::info!("[*] hunting for a working MASQUE gateway (deep connect-ip verification)");
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
                local_ipv4: identity
                    .ipv4
                    .parse()
                    .unwrap_or(std::net::Ipv4Addr::new(172, 16, 0, 2)),
                config_path: base_config.to_string(),
            };

            // Smart reconnect: re-verify the last working gateway before paying
            // for a full scan. Skip with AETHER_QUICK_RECONNECT=0; force with =1.
            if quick_reconnect_enabled() {
                let cache_path = lastconn::cache_path(base_config);
                if let Some(cached) = lastconn::load(&cache_path) {
                    if let Ok(peer_addr) = cached.peer.parse::<SocketAddr>() {
                        log::info!("[*] verifying cached gateway {peer_addr} before reuse");
                        if let Ok(_rtt) = quick_verify_masque(
                            identity,
                            peer_addr,
                            &probe.sni,
                            ech_config.as_deref(),
                        ).await {
                            log::info!("[+] cached gateway {peer_addr} still works; skipping scan");
                            crate::cache::record_success(base_config, peer_addr, true);
                            session_event::emit(SessionEvent::EndpointSelected {
                                addr: peer_addr.to_string(),
                                protocol: "masque".into(),
                            });
                            return Ok(peer_addr);
                        } else {
                            log::warn!("[-] cached gateway {peer_addr} no longer works; scanning fresh");
                            // Evict the dead peer from the trust cache so we stop
                            // trying it first on every reconnect after a network change.
                            crate::cache::record_failure(base_config, peer_addr, true);
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
            lastconn::save(
                &lastconn::cache_path(base_config),
                &peer.to_string(),
                "",
            );
            session_event::emit(SessionEvent::EndpointSelected {
                addr: format!("{}:{}", best.ip, best.port),
                protocol: "masque".into(),
            });
            Ok(peer)
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
                local_ipv4: identity
                    .ipv4
                    .parse()
                    .map_err(|_| AetherError::Other("invalid ipv4".into()))?,
                aethernoize: aethernoize_config(),
                ports: wireguard::WG_PORTS.to_vec(),
                ip,
                config_path: base_config.to_string(),
            };

            let best = prober::hunt_best_wg_endpoint(&probe, mode).await?;
            log::info!(
                "[+] selected WireGuard endpoint {}:{} (rtt {:?})",
                best.ip,
                best.port,
                best.rtt
            );
            Ok(SocketAddr::new(best.ip, best.port))
        }
    }
}

/// Smart reconnect gating. Defaults ON (column requested); turn off via
/// AETHER_QUICK_RECONNECT=0/false/no/off, force-on via =1/true/yes/on. Forcing
/// only matters when nothing is cached (in which case there is nothing to
/// verify anyway, so force-on is effectively the same as default here).
fn quick_reconnect_enabled() -> bool {
    match std::env::var("AETHER_QUICK_RECONNECT").as_deref() {
        Ok("0") | Ok("false") | Ok("no") | Ok("off") => false,
        Ok("1") | Ok("true") | Ok("yes") | Ok("on") => true,
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
    let local_ipv4: std::net::Ipv4Addr = identity
        .ipv4
        .parse()
        .unwrap_or(std::net::Ipv4Addr::new(172, 16, 0, 2));

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
    };
    quic::verify_masque(&vp).await
}

async fn resolve_ech() -> Option<Vec<u8>> {
    match std::env::var("AETHER_ECH") {
        Ok(v) if v == "0" || v.eq_ignore_ascii_case("off") || v.eq_ignore_ascii_case("disable") => {
            log::info!("[+] ECH explicitly disabled via AETHER_ECH={v}");
            None
        }
        Ok(v) if v.eq_ignore_ascii_case("auto") => match dns::fetch_ech_config().await {
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
        Ok(b64) if !b64.is_empty() => match tls::decode_ech_config_list(&b64) {
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
            // Default: auto-fetch ECH to hide SNI from passive observers.
            match dns::fetch_ech_config().await {
                Ok(raw) => {
                    log::info!(
                        "[+] fetched ECHConfigList automatically ({} bytes) — SNI encrypted",
                        raw.len()
                    );
                    Some(raw)
                }
                Err(e) => {
                    log::debug!("[-] ECH auto-fetch failed ({e}); continuing with cleartext SNI");
                    None
                }
            }
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
    let mtu_val = mtu::resolve_mtu("masque").await;
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
            log::info!("[+] H3 data-plane MTU capped to {capped} (was {mtu_val}) to fit QUIC DATAGRAM");
        }
        capped
    };
    let (chans, internals) = quic::channels();

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
        local_ipv4: identity
            .ipv4
            .parse()
            .unwrap_or(std::net::Ipv4Addr::new(172, 16, 0, 2)),
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

    let (addr_tx, mut addr_rx) = tokio::sync::mpsc::channel::<quic::AssignedAddr>(8);
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
    let probe_src: Option<std::net::Ipv4Addr> = identity.ipv4.parse().ok();

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

    match tokio::time::timeout(Duration::from_secs(45), ready_rx).await {
        Ok(Ok(())) => {
            if stack.is_some() {
                session_event::emit(SessionEvent::ProxyReady {
                    socks: listen.to_string(),
                    http: http_listen.to_string(),
                });
            }
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
                "tunnel closed before data-plane ready".into(),
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
                "timeout waiting for MASQUE data-plane".into(),
            ));
        }
    }

    // Supervise the tunnel AND the proxy servers together. If the tunnel task dies
    // (peer dropped, transport error) OR a proxy listener exits, tear the rest down
    // and return so the caller's reconnect loop regains control. Awaiting only the
    // tunnel (as before) let a dead SOCKS listener sit undetected behind a live
    // tunnel, and vice-versa — the "connected but no traffic" silent hang.
    let mut tunnel_handle = tunnel_handle;
    let tunnel_result: Result<()> = tokio::select! {
        r = &mut tunnel_handle => match r {
            Ok(inner) => inner,
            Err(e) => Err(AetherError::Other(format!("tunnel task: {e}"))),
        },
        _ = await_opt(&mut socks_task) => Err(AetherError::Other("socks5 server exited".into())),
        _ = await_opt(&mut http_task) => Err(AetherError::Other("http proxy exited".into())),
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

fn wg_keepalive_secs() -> u16 {
    std::env::var("AETHER_WG_KEEPALIVE")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|&v| v > 0)
        .unwrap_or(5)
}

async fn run_wireguard(
    identity: account::Identity,
    listen: SocketAddr,
    http_listen: SocketAddr,
    base_config: &str,
) -> Result<()> {
    let forced = std::env::var("AETHER_WG_PEER")
        .ok()
        .or_else(|| std::env::var("AETHER_PEER").ok());

    let private_key = identity.private_key_bytes()?;
    let peer_public = identity.peer_public_key_bytes()?;
    let ipv4: std::net::Ipv4Addr = identity
        .ipv4
        .parse()
        .map_err(|_| AetherError::Other("invalid ipv4".into()))?;

    let primary_profile =
        runtime_env::var("AETHER_NOIZE").unwrap_or_else(|| "balanced".to_string());
    let profile = obfuscation::aethernoize_from_name(&primary_profile);

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
    });
    run_wireguard_tunnel(identity, peer, profile, listen, http_listen).await
}

async fn run_wireguard_tunnel(
    identity: account::Identity,
    peer: SocketAddr,
    aethernoize: aethernoize::AetherNoizeConfig,
    listen: SocketAddr,
    http_listen: SocketAddr,
) -> Result<()> {
    // Critical: do NOT open a separate verify session then a second Tunn.
    // Cloudflare edges rate-limit / confuse double handshakes; the old path
    // left SOCKS up on a fresh unestablished tunnel → CONNECT hangs forever.
    let private_key = identity.private_key_bytes()?;
    let peer_public = identity.peer_public_key_bytes()?;
    let mtu = crate::mtu::resolve_mtu("wireguard").await;
    log::info!("[+] using MTU={mtu} for wireguard session");

    let cfg = wireguard::WgConfig {
        local_private_key: private_key,
        peer_public_key: peer_public,
        peer_endpoint: peer,
        client_id: identity.client_id,
        preshared_key: None,
        persistent_keepalive: Some(wg_keepalive_secs()),
        aethernoize: std::sync::Arc::new(aethernoize),
    };

    let (tchans, tints) = tunnel::channels();
    let wg_tunnel = wireguard::WgTunnel::new(cfg, tints.inbound_tx).await?;

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

    let (socks_task, http_task) = if let Some(stack) = stack {
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
    session_event::emit(SessionEvent::Connected {
        detail: if socks_task.is_some() {
            "wireguard proxies up".into()
        } else {
            "wireguard full-device tunnel ready".into()
        },
    });

    let tunnel_result = wg_tunnel.run(tints.outbound_rx).await;
    if let Some(task) = &socks_task {
        task.abort();
    }
    if let Some(task) = &http_task {
        task.abort();
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
) -> Result<(Option<netstack::StackHandle>, Option<routing_plane::TunGuard>)> {
    routing_plane::spawn(ipv4, ipv6, peer, mtu, inbound_rx, outbound_tx).await
}

async fn establish_wg(
    identity: &account::Identity,
    peer: SocketAddr,
    mtu: usize,
    obfuscate: bool,
    keepalive: u16,
    label: &'static str,
) -> Result<netstack::StackHandle> {
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
        preshared_key: None,
        persistent_keepalive: Some(keepalive),
        aethernoize: std::sync::Arc::new(profile),
    };

    let (outbound_tx, outbound_rx) = tokio::sync::mpsc::channel(2048);
    let (inbound_tx, inbound_rx) = tokio::sync::mpsc::channel(2048);

    let wg_tunnel = wireguard::WgTunnel::new(cfg, inbound_tx).await?;

    let stack = netstack::spawn(&identity.ipv4, &identity.ipv6, mtu, inbound_rx, outbound_tx)?;

    tokio::spawn(async move {
        if let Err(e) = wg_tunnel.run(outbound_rx).await {
            log::error!("[{label}] wireguard tunnel exited: {e}");
        }
    });

    Ok(stack)
}

async fn spawn_udp_forwarder(
    outer: &netstack::StackHandle,
    remote: SocketAddr,
) -> Result<SocketAddr> {
    let sock = std::sync::Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await?);
    let local = sock.local_addr()?;

    let udp = outer.open_udp().await?;
    let (udp_tx, mut udp_rx) = udp.into_split();

    let inner_peer: std::sync::Arc<tokio::sync::Mutex<Option<SocketAddr>>> =
        std::sync::Arc::new(tokio::sync::Mutex::new(None));

    let up_sock = sock.clone();
    let up_peer = inner_peer.clone();
    tokio::spawn(async move {
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
    tokio::spawn(async move {
        while let Some((_src, data)) = udp_rx.recv().await {
            let dst = *down_peer.lock().await;
            if let Some(dst) = dst {
                let _ = down_sock.send_to(&data, dst).await;
            }
        }
    });

    Ok(local)
}

async fn run_warp_in_warp(
    primary: account::Identity,
    secondary: account::Identity,
    peer: SocketAddr,
    listen: SocketAddr,
    http_listen: SocketAddr,
) -> Result<()> {
    let _ = mtu::resolve_mtu("wireguard").await;
    log::info!("[*] establishing outer WARP tunnel to {peer}...");
    let outer_stack = establish_wg(&primary, peer, tunnel_mtu(), true, 5, "outer").await?;

    tokio::time::sleep(Duration::from_millis(1500)).await;

    let forwarder = spawn_udp_forwarder(&outer_stack, peer).await?;
    log::info!("[+] inner endpoint tunneled through outer warp via {forwarder}");

    log::info!("[*] establishing inner WARP tunnel (warp-in-warp)...");
    let inner_stack =
        establish_wg(&secondary, forwarder, inner_mtu(), false, 20, "inner").await?;

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
    session_event::emit(SessionEvent::Connected {
        detail: "warp-in-warp ready".into(),
    });
    let result = socks::serve_listener(socks_listener, inner_stack).await;
    http_task.abort();
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
    if let Ok(v) = std::env::var("AETHER_PROTOCOL") {
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
