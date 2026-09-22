//! Standalone H3 (CONNECT-IP over QUIC) diagnostic probe.
//!
//! Enabled with `AETHER_H3_PROBE=<ip:port>`. Runs one edge through a matrix of
//! SNI x header-recipe x ECH x datagram-mode x authority using the real
//! [`crate::quic::verify_masque`] path (which emits per-stage
//! `AETHER_EVENT h3_stage` lines and honors `AETHER_QLOG_DIR` / `SSLKEYLOGFILE`),
//! then prints a summary table of the stage each combination reached.
//!
//! `AETHER_H3_BRUTE=1` switches to the CONNECT-IP request-shape sweep used to
//! crack a 400/403: transport and TLS axes are held fixed (they are proven) and
//! only the request varies -- `:authority` x `:path` x `:protocol` -- with the
//! Cloudflare custom headers riding alongside extended CONNECT.
//!
//! Read-only: it never starts a tunnel.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use crate::account::Identity;
use crate::consts;
use crate::error::Result;
use crate::masque::{H3DgramMode, H3HeaderMode};
use crate::quic::{self, VerifyParams};

const PROBE_TIMEOUT: Duration = Duration::from_secs(8);

struct Combo {
    sni: &'static str,
    headers: H3HeaderMode,
    ech_label: &'static str,
    ech: Option<Vec<u8>>,
    dgram: H3DgramMode,
    authority: String,
    path: String,
    /// Overrides the CONNECT-IP protocol token for this combo when set.
    proto: Option<&'static str>,
}

/// Probe `edge` across the selected matrix and log a summary table.
pub async fn run_probe(edge: SocketAddr, identity: &Identity, ech: Option<Vec<u8>>) -> Result<()> {
    let local_ipv4: Ipv4Addr = identity
        .ipv4
        .parse()
        .unwrap_or_else(|_| Ipv4Addr::new(172, 16, 0, 2));

    let base_authority = crate::runtime_env::var("AETHER_MASQUE_H3_AUTHORITY")
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| quic::default_authority().to_string());
    let base_path = crate::runtime_env::var("AETHER_MASQUE_H3_PATH")
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| quic::default_path().to_string());
    let noize = crate::obfuscation::masque_from_env();
    // Emit per-stage h3_stage events from verify_masque for every combo.
    crate::runtime_env::set("AETHER_H3_TRACE", "1");

    let brute = crate::runtime_env::flag("AETHER_H3_BRUTE");
    let combos: Vec<Combo> = if brute {
        build_brute_matrix(&ech)
    } else {
        build_default_matrix(&ech, &base_authority, &base_path)
    };

    log::info!(
        "[h3-probe] target={edge} local_ipv4={local_ipv4} mode={} combos={} (timeout {:?} each)",
        if brute {
            "brute-request-shape"
        } else {
            "diagnostic"
        },
        combos.len(),
        PROBE_TIMEOUT,
    );

    let mut rows: Vec<String> = Vec::new();
    for c in &combos {
        // The datagram axis is read from the process env at data-plane time; each
        // probe is awaited fully before the next, so there is no cross-combo race.
        crate::runtime_env::set("AETHER_MASQUE_H3_DGRAM", c.dgram.label());

        let vp = VerifyParams {
            peer: edge,
            sni: c.sni.to_string(),
            authority: c.authority.clone(),
            path: c.path.clone(),
            cert_pem: identity.cert_pem.clone(),
            key_pem: identity.key_pem.clone(),
            ech_config_list: c.ech.clone(),
            noize: noize.clone(),
            timeout: PROBE_TIMEOUT,
            local_ipv4,
            header_mode: c.headers,
            protocol: c.proto,
        };
        let started = Instant::now();
        let outcome = match quic::verify_masque(&vp).await {
            Ok(rtt) => format!("OK (data-plane) rtt={rtt:?}"),
            Err(e) => format!("FAIL: {e}"),
        };
        let row = format!(
            "proto={} authority={} path={} sni={} headers={} ech={} dgram={} elapsed={:?} -> {outcome}",
            c.proto.unwrap_or("(default)"),
            c.authority,
            c.path,
            c.sni,
            c.headers.label(),
            c.ech_label,
            c.dgram.label(),
            started.elapsed(),
        );
        log::info!("[h3-probe] {row}");
        rows.push(row);
    }

    log::info!("[h3-probe] ===================== SUMMARY =====================");
    for r in &rows {
        log::info!("[h3-probe] {r}");
    }
    log::info!(
        "[h3-probe] =================== END ({} combos) ===================",
        rows.len()
    );
    log::info!(
        "[h3-probe] Reading the table: 'no UDP reply' = UDP/QUIC filtered; \
         'closed before 200' = handshake/TLS/SNI/ECH; 'status N' = request rejected \
         (400 malformed, 403 unauthorized); 'data-plane probe timeout' = 200 ok but no traffic."
    );
    Ok(())
}

/// CONNECT-IP request-shape sweep for cracking a 400/403.
///
/// The transport/TLS axes are already proven, so this holds SNI fixed and varies
/// only the request. `:authority` is tried with and without the `:443` suffix the
/// working H2 path uses ([`crate::masque_h2`] builds `<authority>:443`). Headers
/// are [`H3HeaderMode::Both`] so Cloudflare's custom `cf-connect-proto` +
/// `pq-enabled` ride alongside the RFC 9220 extended-CONNECT pseudo-headers.
fn build_brute_matrix(_ech: &Option<Vec<u8>>) -> Vec<Combo> {
    let authorities = [
        format!("{}:443", quic::default_authority()),
        quic::default_authority().to_string(),
        format!("{}:443", consts::CONNECT_SNI),
        consts::CONNECT_SNI.to_string(),
    ];
    let paths = ["/", "/.well-known/masque/ip/*/*/"];
    let protos = ["connect-ip", "cf-connect-ip"];

    let mut out = Vec::new();
    for authority in &authorities {
        for path in paths {
            for proto in protos {
                out.push(Combo {
                    sni: consts::CONNECT_SNI,
                    headers: H3HeaderMode::Both,
                    ech_label: "no-ech",
                    ech: None,
                    dgram: H3DgramMode::Auto,
                    authority: authority.clone(),
                    path: path.to_string(),
                    proto: Some(proto),
                });
            }
        }
    }
    out
}

/// The original diagnostic matrix: SNI x headers x ECH, plus focused
/// datagram-mode and authority sweeps against the best-guess recipe.
fn build_default_matrix(
    ech: &Option<Vec<u8>>,
    base_authority: &str,
    base_path: &str,
) -> Vec<Combo> {
    let mut combos: Vec<Combo> = Vec::new();
    // Control combo (runs first): a neutral SNI every Cloudflare edge has a cert
    // for. With the former ambient TLS kill-switch=1, reaching quic_established here
    // while the consumer-masque SNIs fail at TLS proves the ClientHello is fine.
    combos.push(Combo {
        sni: "cloudflare.com",
        headers: H3HeaderMode::Cf,
        ech_label: "control-no-ech",
        ech: None,
        dgram: H3DgramMode::Auto,
        authority: base_authority.to_string(),
        path: base_path.to_string(),
        proto: None,
    });
    for sni in [consts::CONNECT_SNI, consts::L4_CONNECT_SNI] {
        for headers in [H3HeaderMode::Cf, H3HeaderMode::Standard, H3HeaderMode::Both] {
            for (ech_label, ev) in [("ech", ech.clone()), ("no-ech", None)] {
                combos.push(Combo {
                    sni,
                    headers,
                    ech_label,
                    ech: ev,
                    dgram: H3DgramMode::Auto,
                    authority: base_authority.to_string(),
                    path: base_path.to_string(),
                    proto: None,
                });
            }
        }
    }
    // Datagram-mode sweep (best-guess recipe, both explicit modes).
    for dgram in [H3DgramMode::Quic, H3DgramMode::Capsule] {
        combos.push(Combo {
            sni: consts::CONNECT_SNI,
            headers: H3HeaderMode::Cf,
            ech_label: "ech",
            ech: ech.clone(),
            dgram,
            authority: base_authority.to_string(),
            path: base_path.to_string(),
            proto: None,
        });
    }
    // Authority sweep: try the SNI host as :authority (some proxies require it).
    combos.push(Combo {
        sni: consts::CONNECT_SNI,
        headers: H3HeaderMode::Cf,
        ech_label: "ech",
        ech: ech.clone(),
        dgram: H3DgramMode::Auto,
        authority: consts::CONNECT_SNI.to_string(),
        path: base_path.to_string(),
        proto: None,
    });
    combos
}

const FP_CONCURRENCY: usize = 6;
const FP_TIMEOUT: Duration = Duration::from_secs(3);
/// Max hosts probed per /24. MASQUE VIPs cluster at low host numbers (observed:
/// .1/.2 are MASQUE, .128 is a generic HTTP/3 edge), and sweeping the full 254
/// rapidly can abort the BoringSSL stack, so cap to the VIP range.
const FP_MAX_HOSTS_PER_24: u16 = 64;

/// Fingerprint-scan candidates to enumerate MASQUE-capable endpoints (Phase 4).
///
/// `AETHER_H3_FINGERPRINT` is either `A.B.C.0/24` (expands to .1-.254 on 443) or a
/// comma-separated list of `ip:port` (v4 or `[v6]:port`). Each candidate's H3
/// SETTINGS are read; endpoints advertising Extended CONNECT + H3 DATAGRAM are
/// MASQUE-capable. This precedes any auth gate, so it needs no working identity
/// beyond a cert to present. Emits the discovered endpoints and their /24s.
pub async fn run_fingerprint(spec: &str, identity: &Identity) -> Result<()> {
    // Read-only classification: `quic::fingerprint_h3` builds its TLS config
    // with VerifyPolicy::ReadOnlyProbe, so no pins are required and — unlike the
    // previous `runtime_env::set` of a process-wide kill-switch — nothing here
    // can affect verification for tunnel traffic. (That set call was also inert:
    // the readers still used std::env, so the probe's advertised mode never
    // applied.)
    let sni = quic::resolve_h3_sni();
    let cert = identity.cert_pem.clone();
    let key = identity.key_pem.clone();
    let targets = expand_targets(spec);
    if targets.is_empty() {
        // A `/16`, a typo, or a list of unparsable entries expands to nothing. The
        // scan then logged "scanning 0 candidates", probed nothing, and exited 0 —
        // indistinguishable from "probed the whole list, found nothing reachable",
        // which is exactly how a broken spec reads as a negative result.
        return Err(crate::error::AetherError::Other(format!(
            "h3-fingerprint: target spec {spec:?} expands to no candidates \
             (want a comma-separated ip:port list or an A.B.C.0/24 base)"
        )));
    }
    log::info!(
        "[h3-fp] scanning {} candidates (sni={sni}, {} concurrent, {:?} each)",
        targets.len(),
        FP_CONCURRENCY,
        FP_TIMEOUT,
    );

    let mut masque: Vec<SocketAddr> = Vec::new();
    let mut reachable = 0usize;
    let mut idx = 0usize;
    while idx < targets.len() {
        let end = (idx + FP_CONCURRENCY).min(targets.len());
        let mut set = tokio::task::JoinSet::new();
        for &t in &targets[idx..end] {
            let (s, c, k) = (sni.clone(), cert.clone(), key.clone());
            set.spawn(async move { (t, quic::fingerprint_h3(t, &s, &c, &k, FP_TIMEOUT).await) });
        }
        while let Some(res) = set.join_next().await {
            if let Ok((t, Ok(fp))) = res {
                if fp.reachable {
                    reachable += 1;
                }
                if fp.is_masque() {
                    log::info!("[h3-fp] MASQUE endpoint: {t} (ext_connect + dgram)");
                    masque.push(t);
                }
            }
        }
        idx = end;
    }

    masque.sort();
    log::info!(
        "[h3-fp] ==== RESULT: {} MASQUE endpoints / {} reachable / {} scanned ====",
        masque.len(),
        reachable,
        targets.len(),
    );
    for m in &masque {
        log::info!("[h3-fp] masque {m}");
    }
    let mut nets: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for m in &masque {
        if let IpAddr::V4(v4) = m.ip() {
            let o = v4.octets();
            nets.insert(format!("{}.{}.{}.0/24", o[0], o[1], o[2]));
        }
    }
    if !nets.is_empty() {
        log::info!(
            "[h3-fp] MASQUE /24s: {}",
            nets.into_iter().collect::<Vec<_>>().join(", ")
        );
    }
    Ok(())
}

/// Expand a fingerprint spec into candidate `ip:port`s: an `A.B.C.0/24` base
/// (hosts .1-.254 on 443) or a comma-separated `ip:port` list.
fn expand_targets(spec: &str) -> Vec<SocketAddr> {
    let spec = spec.trim();
    if let Some((base, mask)) = spec.split_once('/') {
        if mask.trim() == "24" {
            if let Ok(net) = base.trim().parse::<Ipv4Addr>() {
                let o = net.octets();
                return (1u16..=FP_MAX_HOSTS_PER_24)
                    .map(|h| SocketAddr::from((Ipv4Addr::new(o[0], o[1], o[2], h as u8), 443)))
                    .collect();
            }
        }
    }
    spec.split(',')
        .filter_map(|s| s.trim().parse::<SocketAddr>().ok())
        .collect()
}
