use std::ffi::c_void;
use std::os::raw::c_int;
use std::ptr;

use boring::pkey::PKey;
use boring::ssl::{SslContextBuilder, SslMethod, SslVerifyMode, SslVersion};
use boring::x509::X509;
use foreign_types_shared::ForeignTypeRef;

use crate::consts;
use crate::error::{AetherError, Result};

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
    if dangerous {
        builder.set_verify(SslVerifyMode::NONE);
        static DANGER_WARN: std::sync::Once = std::sync::Once::new();
        DANGER_WARN.call_once(|| {
            log::warn!("[tls] DANGER: server authentication explicitly disabled");
        });
    } else {
        if let Ok(path) = std::env::var("AETHER_TLS_CA_FILE") {
            builder.set_ca_file(path.trim())
                .map_err(|e| AetherError::Tls(format!("load TLS CA file: {e}")))?;
        } else {
            builder.set_default_verify_paths()
                .map_err(|e| AetherError::Tls(format!("load system TLS roots: {e}")))?;
        }
        builder.set_verify(SslVerifyMode::PEER);
    }

    let mut config = quiche::Config::with_boring_ssl_ctx_builder(quiche::PROTOCOL_VERSION, builder)
        .map_err(AetherError::Quic)?;

    config.verify_peer(!dangerous);

    config
        .set_application_protos(&[consts::ALPN_H3, b"h3-29"])
        .map_err(AetherError::Quic)?;

    config.set_max_idle_timeout(120_000);
    // Match raised tunnel MTU / typical path MTU for fewer QUIC packets.
    config.set_max_recv_udp_payload_size(1350);
    config.set_max_send_udp_payload_size(1350);
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
