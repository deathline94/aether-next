use std::ffi::c_void;
use std::os::raw::c_int;
use std::ptr;

use boring::pkey::PKey;
use boring::ssl::{SslContextBuilder, SslMethod, SslVerifyMode, SslVersion};
use boring::x509::X509;
use foreign_types_shared::ForeignTypeRef;

use crate::consts;
use crate::error::{AetherError, Result};

/// Compute SHA-256 hash of a certificate's SubjectPublicKeyInfo (SPKI).
fn spki_sha256(cert: &boring::x509::X509Ref) -> Option<[u8; 32]> {
    let pubkey = cert.public_key().ok()?;
    let der = pubkey.public_key_to_der().ok()?;
    use ring::digest;
    let hash = digest::digest(&digest::SHA256, &der);
    let mut out = [0u8; 32];
    out.copy_from_slice(hash.as_ref());
    Some(out)
}

fn hex32(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Is the leaf inside its own validity window?
///
/// This check did not exist at all before: the verify callback discarded
/// BoringSSL's precomputed result, so no signature, chain, **validity period**
/// or hostname check was performed. A committed SPKI pin therefore kept
/// authenticating a certificate years after it expired, and an edge that
/// presented a *not-yet-valid* leaf (clock skew, misprovisioned deployment) was
/// accepted just as happily.
fn leaf_is_temporally_valid(leaf: &boring::x509::X509Ref, now_unix: u64) -> std::result::Result<(), String> {
    use boring::asn1::Asn1Time;
    // `time_t` is 64-bit on the desktop ABIs and 32-bit on the 32-bit Android
    // ones, so the conversion must follow the target instead of naming a width
    // that only compiles half the time. Refuse rather than compare against a
    // silently truncated "now".
    if cfg!(target_pointer_width = "32") && now_unix > u64::from(i32::MAX) {
        return Err("system clock beyond 32-bit time_t range".into());
    }
    let now = Asn1Time::from_unix(now_unix as _).map_err(|e| format!("clock: {e}"))?;
    let not_before = leaf.not_before();
    let not_after = leaf.not_after();
    if now < not_before {
        return Err("leaf certificate is not yet valid".into());
    }
    if not_after <= now {
        return Err("leaf certificate has expired".into());
    }
    Ok(())
}

/// Install SPKI pinning **on top of** normal verification.
///
/// Previously this installed a callback of the shape
/// `move |_ok, ctx| { ...pin match... }`, which threw away `_ok`. In BoringSSL a
/// `set_verify_callback` result is authoritative: the callback *replaces*
/// chain building, so the handshake validated nothing but a hash. An attacker
/// holding a copy of a pinned edge key — or any CA that ever minted a
/// cloudflare-looking cert while hostname checks were globally off — could MITM
/// the tunnel.
///
/// The pinned-SPKI check is retained as the primary mechanism (correct for the
/// self-signed consumer MASQUE leaf), but it is now *additive*: leaf validity is
/// always enforced, and full chain building runs for any host whose
/// [`PinSet::require_chain`] is set.
pub fn install_pin_verification(
    builder: &mut SslContextBuilder,
    sets: &[crate::trust::PinSet],
    host: &str,
) -> Result<()> {
    let set = sets
        .iter()
        .find(|s| s.host.eq_ignore_ascii_case(host))
        .ok_or_else(|| {
            AetherError::Tls(format!(
                "no pinned key set for host {host:?}; refusing to connect unverified"
            ))
        })?;
    if set.pins.is_empty() {
        return Err(AetherError::Tls(format!(
            "pin set for {host:?} is empty; refusing to fall back to no-verify"
        )));
    }
    let pins: Vec<([u8; 32], u64)> = set
        .pins
        .iter()
        .filter_map(|p| hex_to_32(&p.spki_sha256).map(|h| (h, p.expires_unix)))
        .collect();
    if pins.is_empty() {
        return Err(AetherError::Tls(format!(
            "pin set for {host:?} contains no well-formed SHA-256 digests"
        )));
    }
    let require_chain = set.require_chain;
    let host_owned = host.to_string();
    builder.set_verify_callback(SslVerifyMode::PEER, move |ok, ctx| {
        let host = host_owned.as_str();
        let now = crate::trust::now_unix();
        // Runs before `ctx.chain()` because both need `ctx` and verify_cert
        // takes it mutably.
        if require_chain && !(ok && ctx.verify_cert().unwrap_or(false)) {
            log::error!("[tls] {host:?}: certificate chain verification failed");
            return false;
        }
        let Some(chain) = ctx.chain() else {
            log::error!("[tls] peer sent no certificate chain for {host:?}");
            return false;
        };
        let Some(leaf) = chain.iter().next() else {
            log::error!("[tls] empty certificate chain for {host:?}");
            return false;
        };
        if let Err(reason) = leaf_is_temporally_valid(leaf, now) {
            log::error!("[tls] {host:?}: {reason}");
            return false;
        }
        let Some(hash) = spki_sha256(leaf) else {
            log::error!("[tls] {host:?}: cannot read leaf SPKI");
            return false;
        };
        let matched = pins
            .iter()
            .any(|(pinned, expires)| *expires > now && pinned == &hash);
        if !matched {
            // Was `log::debug!`, i.e. invisible at the default filter: a key
            // rotation looked like "network blocks QUIC" rather than what it was.
            log::error!(
                "[tls] SPKI pin mismatch for {host:?}: observed {} — rejecting. \
                 If the edge key rotated, refresh packaging/trust/masque-pins.json.",
                hex32(&hash)
            );
        }
        matched
    });
    Ok(())
}

fn hex_to_32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let bytes = (0..32)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok())
        .collect::<Option<Vec<u8>>>()?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Some(out)
}

extern "C" {
    fn SSL_set1_ech_config_list(
        ssl: *mut c_void,
        ech_config_list: *const u8,
        ech_config_list_len: usize,
    ) -> c_int;

    fn SSL_get0_ech_retry_configs(
        ssl: *const c_void,
        out_retry_configs: *mut *const u8,
        out_retry_configs_len: *mut usize,
    );
}

const CHROME_GROUPS: &str = "X25519:P-256:P-384";

pub struct TlsParams<'a> {
    pub cert_pem: &'a [u8],
    pub key_pem: &'a [u8],
    /// Host whose [`crate::trust::PinSet`] authenticates this peer. Pass the
    /// pinned identity host (`consts::CONNECT_SNI`), *not* a fronted SNI value:
    /// the pin set is the trust decision, and fronting must not be able to
    /// change which key is trusted.
    pub pin_host: &'a str,
    pub policy: crate::trust::VerifyPolicy<'a>,
}

pub fn build_config(params: &TlsParams) -> Result<quiche::Config> {
    let mut builder = SslContextBuilder::new(SslMethod::tls())
        .map_err(|e| AetherError::Tls(e.to_string()))?;

    builder
        .set_min_proto_version(Some(SslVersion::TLS1_3))
        .map_err(|e| AetherError::Tls(e.to_string()))?;
    builder
        .set_max_proto_version(Some(SslVersion::TLS1_3))
        .map_err(|e| AetherError::Tls(e.to_string()))?;

    builder.set_grease_enabled(true);

    // #3: Rotate ClientHello profile per-session. Randomize cipher suite order
    // so JA3/JA4 fingerprints differ across connections, defeating DPI caching.
    let cipher_sets: &[&str] = &[
        "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256",
        "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256",
        "TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384",
        "TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384",
    ];
    let idx = rand::random::<usize>() % cipher_sets.len();
    let _ = builder.set_cipher_list(cipher_sets[idx]);

    let groups = crate::runtime_env::var("AETHER_TLS_GROUPS");
    let groups = groups.as_deref().map(str::trim).filter(|s| !s.is_empty()).unwrap_or(CHROME_GROUPS);
    builder
        .set_curves_list(groups)
        .map_err(|e| AetherError::Tls(e.to_string()))?;

    let mut alpn = Vec::with_capacity(consts::ALPN_H3.len() + 1);
    alpn.push(consts::ALPN_H3.len() as u8);
    alpn.extend_from_slice(consts::ALPN_H3);
    builder
        .set_alpn_protos(&alpn)
        .map_err(|e| AetherError::Tls(e.to_string()))?;

    let cert = X509::from_pem(params.cert_pem).map_err(|e| AetherError::Tls(e.to_string()))?;
    let key = PKey::private_key_from_pem(params.key_pem)
        .map_err(|e| AetherError::Tls(e.to_string()))?;
    builder
        .set_certificate(&cert)
        .map_err(|e| AetherError::Tls(e.to_string()))?;
    builder
        .set_private_key(&key)
        .map_err(|e| AetherError::Tls(e.to_string()))?;

    // Verification is decided by an explicit policy passed by the caller, never
    // by an ambient environment variable. The two former TLS kill-switch env
    // vars (names deliberately not repeated here — see the tls-no-ambient-bypass
    // gate) are gone: presence of a variable readable by any local process must
    // not be able to turn off authentication for a tool whose threat model
    // includes a coercible on-path adversary.
    match params.policy {
        crate::trust::VerifyPolicy::Pinned(sets) => {
            // SPKI pinning (mirrors masque_h2): Cloudflare's consumer MASQUE
            // edges present a self-signed or WE1-mixed leaf that is not issued
            // for the dialled IP, so the pinned SPKI *is* the trust anchor.
            // It is now additive with leaf-validity enforcement, and an empty or
            // unusable pin set is a hard error instead of `SslVerifyMode::NONE`.
            install_pin_verification(&mut builder, sets, params.pin_host)?;
        }
        crate::trust::VerifyPolicy::ReadOnlyProbe => {
            builder.set_verify(SslVerifyMode::NONE);
            static PROBE_WARN: std::sync::Once = std::sync::Once::new();
            PROBE_WARN.call_once(|| {
                log::warn!(
                    "[tls] unpinned probe mode: results may include hostile peers; \
                     never used for tunnel traffic"
                );
            });
        }
        #[cfg(debug_assertions)]
        crate::trust::VerifyPolicy::Insecure { reason } => {
            builder.set_verify(SslVerifyMode::NONE);
            log::error!("[tls] DEV BUILD: verification disabled (reason: {reason})");
        }
    }

    let mut config = quiche::Config::with_boring_ssl_ctx_builder(quiche::PROTOCOL_VERSION, builder)
        .map_err(AetherError::Quic)?;

    // Do NOT call config.verify_peer() here: quiche's verify_peer() resets the
    // SSL_CTX verify callback (SSL_CTX_set_verify(..., None)), which would wipe
    // the SPKI pin callback installed on the builder above. The builder already
    // carries the correct verify mode for both the pinned and opt-out paths.

    config
        .set_application_protos(&[consts::ALPN_H3])
        .map_err(AetherError::Quic)?;

    // Idle timeout: 45 s, not 120 s. Two independent reasons:
    //  * the effective timeout is min(local, peer) floored to 3*PTO, so a 120 s
    //    local value is silently shortened by any stricter peer and only ever
    //    delays dead-peer detection (quiche lib.rs:8897-8928);
    //  * NAT/UDP soft state typically expires around 30 s, so a "healthy" 120 s
    //    idle tunnel is usually already black-holing.
    // The 15 s keepalive in quic.rs gives ~3 keepalives inside this window.
    config.set_max_idle_timeout(45_000);
    // UDP payload size (QUIC `max_udp_payload_size` transport param + our send cap).
    let max_udp = crate::runtime_env::usize("AETHER_QUIC_MAX_UDP_PAYLOAD")
        .unwrap_or(1350)
        .clamp(1200, 1452);
    config.set_max_recv_udp_payload_size(max_udp);
    config.set_max_send_udp_payload_size(max_udp);

    // Aether anti-DPI: optionally split the client ClientHello across two QUIC
    // Initial datagrams so on-path DPI that decrypts the first Initial (its keys
    // derive from the clear DCID) can't read the SNI.
    if let Some(frag) = crate::runtime_env::usize("AETHER_QUIC_INITIAL_FRAG") {
        if frag > 0 {
            config.set_initial_crypto_fragment(frag);
            static FRAG_LOG: std::sync::Once = std::sync::Once::new();
            FRAG_LOG.call_once(|| {
                log::info!("[tls] QUIC Initial fragmentation ON: first CRYPTO fragment = {frag} bytes");
            });
        }
    }

    config.set_initial_max_data(10_000_000);
    config.set_initial_max_stream_data_bidi_local(2_000_000);
    config.set_initial_max_stream_data_bidi_remote(2_000_000);
    config.set_initial_max_stream_data_uni(2_000_000);
    config.set_initial_max_streams_bidi(100);
    config.set_initial_max_streams_uni(100);
    config.set_disable_active_migration(true);
    // `enable_dgram(enabled, recv_queue_len, send_queue_len)` — these are QUEUE
    // ENTRY COUNTS, not byte sizes (quiche lib.rs:1198-1208; the advertised
    // max_datagram_frame_size is a fixed 65536). Passing 65536 here permitted
    // ~65 k queued datagrams, i.e. tens of megabytes of unacknowledged inbound
    // memory on a tunnel that can be fed by a remote peer.
    config.enable_dgram(true, crate::tunnel::NET_QUEUE, crate::tunnel::NET_QUEUE);

    Ok(config)
}

pub fn inject_ech(conn: &mut quiche::Connection, ech_config_list: &[u8]) -> Result<()> {
    if ech_config_list.is_empty() {
        return Err(AetherError::Ech("empty ech config list".into()));
    }

    let ssl: &mut boring::ssl::SslRef = conn.as_mut();
    let ssl_ptr = ssl.as_ptr() as *mut c_void;

    let rc = unsafe {
        SSL_set1_ech_config_list(ssl_ptr, ech_config_list.as_ptr(), ech_config_list.len())
    };

    if rc != 1 {
        return Err(AetherError::Ech(format!(
            "SSL_set1_ech_config_list failed (rc={rc})"
        )));
    }

    Ok(())
}

pub fn extract_ech_retry_configs(conn: &mut quiche::Connection) -> Option<Vec<u8>> {
    let ssl: &mut boring::ssl::SslRef = conn.as_mut();
    let ssl_ptr = ssl.as_ptr() as *const c_void;

    let mut out: *const u8 = ptr::null();
    let mut out_len: usize = 0;

    unsafe {
        SSL_get0_ech_retry_configs(ssl_ptr, &mut out, &mut out_len);
    }

    if out.is_null() || out_len == 0 {
        return None;
    }

    let slice = unsafe { std::slice::from_raw_parts(out, out_len) };
    Some(slice.to_vec())
}

pub fn decode_ech_config_list(b64: &str) -> Result<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .map_err(|e| AetherError::Ech(e.to_string()))
}
