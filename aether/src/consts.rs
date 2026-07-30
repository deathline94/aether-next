pub const API_URL: &str = "https://api.cloudflareclient.com";
pub const API_VERSION: &str = "v0a4471";

pub const CONNECT_SNI: &str = "consumer-masque.cloudflareclient.com";
pub const L4_CONNECT_SNI: &str = "consumer-masque-proxy.cloudflareclient.com";

/// Default MASQUE (CONNECT-IP over QUIC) data-plane endpoint. This is the stable
/// consumer-masque anycast VIP returned by the WARP enroll_key API (verified live:
/// tunnel_ready h3 + curl). Used as the H3 peer when the identity has no captured
/// endpoint and no peer is forced -- the generic CDN scan does not reliably hit the
/// MASQUE VIP (most edges are generic HTTP/3, ext_connect=false).
pub const MASQUE_H3_ENDPOINT: &str = "162.159.198.2:443";

/// SHA-256 SPKI hashes of Cloudflare MASQUE edge certificates.
/// Used for certificate pinning to prevent MITM attacks.
pub const MASQUE_PINS: &[&[u8; 32]] = &[
    // masque.cloudflareclient.com — self-signed by Cloudflare
    b"\xeb\x59\x1b\x36\xab\x26\xba\x61\x7e\x98\x37\x19\x18\xc1\x0b\xcd\xea\xe3\x74\x2d\xb6\xe7\x65\x43\xf9\x4b\xe5\x24\xdc\xe1\xd5\x55",
    // cloudflareaccess.com — signed by Google Trust Services WE1
    b"\x3f\xbb\x1d\x74\x52\xd3\x2b\x38\x81\xeb\x4b\x5d\x48\x42\x14\x45\xb6\xb9\xd8\xf5\x22\x59\x59\xf0\x33\x53\x2d\x50\x26\x37\xb0\x40",
];

pub const DEFAULT_MODEL: &str = "PC";
pub const DEFAULT_LOCALE: &str = "en_US";

pub const KEY_TYPE_MASQUE: &str = "secp256r1";
pub const TUN_TYPE_MASQUE: &str = "masque";

pub const UA_REGISTER: &str = "WARP for Android";
pub const CF_CLIENT_VERSION: &str = "a-6.35-4471";

pub const ALPN_H3: &[u8] = b"h3";

pub const CF_CONNECT_PROTOCOL: &str = "cf-connect-ip";

/// Cloudflare-custom request headers observed on the working H2 CONNECT-IP path.
/// The H3 path can mirror these instead of standards-style extended CONNECT.
pub const CF_CONNECT_PROTO_HEADER: &str = "cf-connect-proto";
pub const CF_PQ_ENABLED_HEADER: &str = "pq-enabled";
pub const CF_PQ_ENABLED_VALUE: &str = "false";

pub const CONNECT_IP_CONTEXT_ID: u64 = 0;
