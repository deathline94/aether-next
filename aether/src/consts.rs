pub const API_URL: &str = "https://api.cloudflareclient.com";
pub const API_VERSION: &str = "v0a4471";

pub const CONNECT_SNI: &str = "consumer-masque.cloudflareclient.com";
pub const L4_CONNECT_SNI: &str = "consumer-masque-proxy.cloudflareclient.com";

/// Default MASQUE (CONNECT-IP over QUIC) data-plane endpoint. This is the stable
/// consumer-masque anycast VIP returned by the WARP enroll_key API (verified live:
/// tunnel_ready h3 + curl). Used as the H3 peer when the identity has no captured
/// endpoint and no peer is forced -- the generic CDN scan does not reliably hit the
/// MASQUE VIP (most edges are generic HTTP/3, ext_connect=false).
#[allow(dead_code)]
pub const MASQUE_H3_ENDPOINT: &str = "162.159.198.2:443";

// SPKI pins live in `packaging/trust/masque-pins.json` (loaded and validated by
// `crate::trust::masque_pin_sets`), not in a byte literal here. A committed
// reviewable file makes a key rotation a visible one-line diff and removes the
// "empty slice means trust everyone" fallback this constant used to enable.

pub const DEFAULT_MODEL: &str = "PC";
pub const DEFAULT_LOCALE: &str = "en_US";

pub const KEY_TYPE_MASQUE: &str = "secp256r1";
pub const TUN_TYPE_MASQUE: &str = "masque";

pub const UA_REGISTER: &str = "WARP for Android";
pub const CF_CLIENT_VERSION: &str = "a-6.35-4471";

pub const ALPN_H3: &[u8] = b"h3";

pub const QUIC_V2_VERSION: u32 = 0x6b33_43cf;
#[allow(dead_code)]
pub const H3_DATAGRAM_00: u64 = 0x276;

pub const CF_CONNECT_PROTOCOL: &str = "cf-connect-ip";

/// Cloudflare-custom request headers observed on the working H2 CONNECT-IP path.
/// The H3 path can mirror these instead of standards-style extended CONNECT.
#[allow(dead_code)]
pub const CF_CONNECT_PROTO_HEADER: &str = "cf-connect-proto";
#[allow(dead_code)]
pub const CF_PQ_ENABLED_HEADER: &str = "pq-enabled";
#[allow(dead_code)]
pub const CF_PQ_ENABLED_VALUE: &str = "false";

pub const CONNECT_IP_CONTEXT_ID: u64 = 0;

#[allow(dead_code)]
pub const CDN_ANYCAST_POOL: &[&str] = &[
    "104.16.0.0",
    "104.17.0.0",
    "104.18.0.0",
    "104.19.0.0",
    "104.20.0.0",
    "104.21.0.0",
    "104.22.0.0",
    "104.24.0.0",
    "104.25.0.0",
    "104.26.0.0",
    "104.27.0.0",
    "104.28.0.0",
    "172.64.0.0",
    "172.65.0.0",
    "172.66.0.0",
    "172.67.0.0",
    "188.114.96.0",
    "188.114.97.0",
    "188.114.98.0",
    "188.114.99.0",
];

#[allow(dead_code)]
pub const QUIC_PORT: u16 = 443;
