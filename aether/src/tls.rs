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

/// Install SPKI certificate pinning on a TLS context builder.
/// If `pins` is non-empty, sets a custom verify callback that checks the leaf
/// cert's SPKI hash against the pinned set. Otherwise falls back to no-verify.
pub fn install_pin_verification(
    builder: &mut SslContextBuilder,
    pins: &'static [&'static [u8; 32]],
) {
    if pins.is_empty() {
        builder.set_verify(SslVerifyMode::NONE);
        return;
    }
    builder.set_verify_callback(SslVerifyMode::PEER, move |_ok, ctx| {
        let Some(chain) = ctx.chain() else { return false };
        let Some(leaf) = chain.iter().next() else { return false };
        let Some(hash) = spki_sha256(leaf) else { return false };
        let matched = pins.iter().any(|pin| pin.as_slice() == hash.as_slice());
        if !matched {
            log::warn!(
                "[tls] SPKI pin mismatch: {:02x?} — refusing connection. If Cloudflare rotated \
                 their edge certificate, update consts::MASQUE_PINS. Debug-only escape hatch: \
                 set AETHER_MASQUE_DISABLE_SPKI_PINS=1",
                &hash[..8]
            );
        }
        matched
    });
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

    let groups = std::env::var("AETHER_TLS_GROUPS").ok();
    let groups = groups.as_deref().map(str::trim).filter(|s| !s.is_empty()).unwrap_or(CHROME_GROUPS);
    builder
        .set_curves_list(groups)
        .map_err(|e| AetherError::Tls(e.to_string()))?;

    let mut alpn = Vec::new();
    alpn.push(consts::ALPN_H3.len() as u8);
    alpn.extend_from_slice(consts::ALPN_H3);
    alpn.push(5);
    alpn.extend_from_slice(b"h3-29");
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

    let dangerous = std::env::var("AETHER_DANGEROUS_DISABLE_TLS_VERIFY")
        .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(false);

    // SPKI certificate pinning (mirrors masque_h2): Cloudflare edges serve
    // self-signed / mixed CA certs per SNI, so instead of trusting the system
    // CA store the leaf cert's SPKI hash is checked against the pinned MASQUE
    // edge set. This prevents MITM by any attacker able to mint a
    // "cloudflare"-looking certificate. Override only for explicit debugging.
    let pins_disabled = std::env::var("AETHER_MASQUE_DISABLE_SPKI_PINS")
        .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(false);

    if dangerous || pins_disabled {
        builder.set_verify(SslVerifyMode::NONE);
        static DANGER_WARN: std::sync::Once = std::sync::Once::new();
        DANGER_WARN.call_once(|| {
            log::warn!("[tls] H3 SPKI pinning disabled (AETHER_DANGEROUS_DISABLE_TLS_VERIFY or AETHER_MASQUE_DISABLE_SPKI_PINS set)");
        });
    } else {
        install_pin_verification(&mut builder, consts::MASQUE_PINS);
    }

    let mut config = quiche::Config::with_boring_ssl_ctx_builder(quiche::PROTOCOL_VERSION, builder)
        .map_err(AetherError::Quic)?;

    // Do NOT call config.verify_peer() here: quiche's verify_peer() resets the
    // SSL_CTX verify callback (SSL_CTX_set_verify(..., None)), which would wipe
    // the SPKI pin callback installed on the builder above. The builder already
    // carries the correct verify mode for both the pinned and opt-out paths.

    config
        .set_application_protos(&[consts::ALPN_H3, b"h3-29"])
        .map_err(AetherError::Quic)?;

    config.set_max_idle_timeout(120_000);
    // UDP payload size (QUIC `max_udp_payload_size` transport param + our send cap).
    // Default 1350 suits ~1420-MTU tunnels; on smaller-MTU paths (e.g. a 1280-MTU
    // WireGuard/WARP tunnel) advertising 1350 makes the peer send handshake packets
    // that exceed the path and get dropped inbound -> "no UDP reply". Env-tunable so
    // small-MTU networks can lower it (floor 1200 = QUIC Initial minimum).
    let max_udp = crate::runtime_env::usize("AETHER_QUIC_MAX_UDP_PAYLOAD")
        .unwrap_or(1350)
        .clamp(1200, 1452);
    config.set_max_recv_udp_payload_size(max_udp);
    config.set_max_send_udp_payload_size(max_udp);
    // Aether anti-DPI: optionally split the client ClientHello across two QUIC
    // Initial datagrams so on-path DPI that decrypts the first Initial (its keys
    // derive from the clear DCID) can't read the SNI. Off unless
    // AETHER_QUIC_INITIAL_FRAG is set to the first-fragment size in bytes; a
    // small value (~64-128) makes the SNI straddle the datagram boundary. The
    // server reassembles multi-packet CRYPTO transparently.
    if let Some(frag) = crate::runtime_env::usize("AETHER_QUIC_INITIAL_FRAG") {
        if frag > 0 {
            config.set_initial_crypto_fragment(frag);
            // Log once per process, not once per probe: build_config runs for
            // every scan candidate, so an unconditional info! here floods the
            // scan output with hundreds of identical lines.
            static FRAG_LOG: std::sync::Once = std::sync::Once::new();
            FRAG_LOG.call_once(|| {
                log::info!("[tls] QUIC Initial fragmentation ON: first CRYPTO fragment = {frag} bytes");
            });
        }
    }
    // CONNECT-IP rides on H3 DATAGRAMS; still raise stream/conn FC for control plane
    // and any non-dgram path. 100MB conn window avoids artificial throttling.
    config.set_initial_max_data(100_000_000);
    config.set_initial_max_stream_data_bidi_local(16_000_000);
    config.set_initial_max_stream_data_bidi_remote(16_000_000);
    config.set_initial_max_stream_data_uni(8_000_000);
    config.set_initial_max_streams_bidi(100);
    config.set_initial_max_streams_uni(100);
    // #6: Enable active migration so QUIC can survive network changes
    // (WiFi→mobile, IP rotation) without a full reconnect.
    config.set_disable_active_migration(false);
    // Larger dgram queues so bulk IP traffic is not dropped under load.
    config.enable_dgram(true, 256_000, 256_000);
    // #1: Enable 0-RTT (early data) for session resumption on reconnect.
    config.enable_early_data();

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
