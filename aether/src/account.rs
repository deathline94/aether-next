use base64::Engine;
use boring::asn1::Asn1Time;
use boring::bn::BigNum;
use boring::ec::{EcGroup, EcKey};
use boring::hash::MessageDigest;
use boring::nid::Nid;
use boring::pkey::PKey;
use boring::x509::{X509Builder, X509NameBuilder, X509};
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::consts;
use crate::error::{AetherError, Result};

#[derive(Debug, Clone, Serialize)]
struct Registration {
    key: String,
    install_id: String,
    fcm_token: String,
    tos: String,
    model: String,
    serial_number: String,
    os_version: String,
    key_type: String,
    tunnel_type: String,
    locale: String,
}

#[derive(Debug, Clone, Serialize)]
struct DeviceUpdate {
    key: String,
    key_type: String,
    tunnel_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AccountData {
    pub id: String,
    #[serde(default)]
    pub token: String,
    #[serde(default)]
    pub config: Config,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub interface: Interface,
    #[serde(default)]
    pub peers: Vec<Peer>,
    #[serde(default)]
    pub client_id: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Peer {
    pub public_key: String,
    #[serde(default)]
    pub endpoint: Endpoint,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Endpoint {
    #[serde(default)]
    pub host: String,
    #[serde(default)]
    pub v4: String,
    #[serde(default)]
    pub v6: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Interface {
    #[serde(default)]
    pub addresses: Addresses,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Addresses {
    #[serde(default)]
    pub v4: String,
    #[serde(default)]
    pub v6: String,
}

// Contains bearer tokens and private keys; never derive Debug.
//
// `ZeroizeOnDrop` because an `Identity` outlives its useful life by hours: the
// access token, the certificate key and the WireGuard scalar sat in heap that
// the allocator happily hands to the next allocation, so anything reading
// process memory after a disconnect still saw them.
#[derive(Clone, zeroize::ZeroizeOnDrop)]
pub struct Identity {
    pub device_id: String,
    pub access_token: String,
    pub cert_pem: Vec<u8>,
    pub key_pem: Vec<u8>,
    pub ipv4: String,
    pub ipv6: String,
    pub wg_private_key: [u8; 32],
    pub wg_peer_public_key: [u8; 32],
    pub client_id: [u8; 3],
    /// MASQUE data-plane endpoint (host:443) from the enroll_key response's first
    /// peer. None for identities provisioned before this was captured; callers
    /// fall back to the known MASQUE anycast.
    pub masque_endpoint: Option<String>,
}

/// Capability view — what this identity can run without re-provisioning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityCapability {
    WireGuardOnly,
    MasqueReady,
}

#[derive(zeroize::ZeroizeOnDrop)]
pub struct MasqueKeyPair {
    pub key_pem: Vec<u8>,
    pub cert_pem: Vec<u8>,
    pub spki_der: Vec<u8>,
}

pub fn generate_masque_keypair() -> Result<MasqueKeyPair> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)
        .map_err(|e| AetherError::Tls(e.to_string()))?;
    let ec = EcKey::generate(&group).map_err(|e| AetherError::Tls(e.to_string()))?;
    let pkey = PKey::from_ec_key(ec).map_err(|e| AetherError::Tls(e.to_string()))?;

    let key_pem = pkey
        .private_key_to_pem_pkcs8()
        .map_err(|e| AetherError::Tls(e.to_string()))?;
    let spki_der = pkey
        .public_key_to_der()
        .map_err(|e| AetherError::Tls(e.to_string()))?;

    let mut builder = X509Builder::new().map_err(|e| AetherError::Tls(e.to_string()))?;
    builder
        .set_version(2)
        .map_err(|e| AetherError::Tls(e.to_string()))?;

    // L5 fix: use a random positive serial instead of a fixed 0, which is an
    // unusual value that makes the client certificate trivially fingerprintable.
    let serial = BigNum::from_slice(&(rand::random::<u64>() | 1).to_be_bytes())
        .and_then(|bn| bn.to_asn1_integer())
        .map_err(|e| AetherError::Tls(e.to_string()))?;
    builder
        .set_serial_number(&serial)
        .map_err(|e| AetherError::Tls(e.to_string()))?;

    let name = X509NameBuilder::new()
        .map_err(|e| AetherError::Tls(e.to_string()))?
        .build();
    builder
        .set_subject_name(&name)
        .map_err(|e| AetherError::Tls(e.to_string()))?;
    builder
        .set_issuer_name(&name)
        .map_err(|e| AetherError::Tls(e.to_string()))?;

    let not_before = Asn1Time::days_from_now(0).map_err(|e| AetherError::Tls(e.to_string()))?;
    // Validity extended to 90 days to avoid premature expiration while keeping
    // automatic re-enrollment when expiration nears.
    let not_after = Asn1Time::days_from_now(90).map_err(|e| AetherError::Tls(e.to_string()))?;
    builder
        .set_not_before(&not_before)
        .map_err(|e| AetherError::Tls(e.to_string()))?;
    builder
        .set_not_after(&not_after)
        .map_err(|e| AetherError::Tls(e.to_string()))?;

    builder
        .set_pubkey(&pkey)
        .map_err(|e| AetherError::Tls(e.to_string()))?;
    builder
        .sign(&pkey, MessageDigest::sha256())
        .map_err(|e| AetherError::Tls(e.to_string()))?;

    let cert_pem = builder
        .build()
        .to_pem()
        .map_err(|e| AetherError::Tls(e.to_string()))?;

    Ok(MasqueKeyPair {
        key_pem,
        cert_pem,
        spki_der,
    })
}

const API_HOST: &str = "api.cloudflareclient.com";

/// Cloudflare anycast edges that front the API. Used to bypass a poisoned or blocked
/// DNS for `api.cloudflareclient.com`: Cloudflare's edge routes by SNI/Host (not IP),
/// so the domain is reachable on any of its anycast IPs with no DNS lookup. TCP/443
/// survives networks that only DPI-drop QUIC, so this keeps first-time signup working
/// where the resolver is tampered.
const API_FALLBACK_EDGES: &[&str] = &["162.159.192.1", "162.159.195.1", "188.114.96.1"];

fn fragmented_http1_enabled() -> bool {
    crate::fragment::FragmentConfig::from_env().enabled
}

struct FragmentedHttpReply {
    status: u16,
    retry_after: Option<std::time::Duration>,
    body: String,
}

fn parse_retry_after_header(value: &str) -> Option<std::time::Duration> {
    value
        .trim()
        .parse::<u64>()
        .ok()
        .map(std::time::Duration::from_secs)
}

fn decode_chunked_body(raw: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    while pos < raw.len() {
        let Some(rel_end) = raw[pos..].windows(2).position(|w| w == b"\r\n") else {
            return Err(AetherError::Api("truncated chunked HTTP response".into()));
        };
        let line = std::str::from_utf8(&raw[pos..pos + rel_end])
            .map_err(|_| AetherError::Api("non-utf8 chunk size".into()))?;
        let hex_len = line.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(hex_len, 16)
            .map_err(|_| AetherError::Api(format!("invalid chunk length {hex_len:?}")))?;
        pos += rel_end + 2;
        if size == 0 {
            return Ok(out);
        }
        let end = pos
            .checked_add(size)
            .ok_or_else(|| AetherError::Api("chunk length overflow".into()))?;
        if end + 2 > raw.len() {
            return Err(AetherError::Api("truncated chunked HTTP payload".into()));
        }
        out.extend_from_slice(&raw[pos..end]);
        pos = end + 2;
    }
    Ok(out)
}

fn parse_http1_reply(raw: &[u8]) -> Result<FragmentedHttpReply> {
    let Some(hdr_end) = raw.windows(4).position(|w| w == b"\r\n\r\n") else {
        return Err(AetherError::Api("malformed HTTP response headers".into()));
    };
    let head = std::str::from_utf8(&raw[..hdr_end])
        .map_err(|_| AetherError::Api("non-utf8 HTTP response headers".into()))?;
    let mut lines = head.split("\r\n");
    let status_line = lines
        .next()
        .ok_or_else(|| AetherError::Api("empty HTTP status line".into()))?;
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or_else(|| AetherError::Api(format!("bad HTTP status line: {status_line}")))?;

    let mut retry_after = None;
    let mut chunked = false;
    let mut content_length: Option<usize> = None;
    for line in lines {
        if let Some((name, val)) = line.split_once(':') {
            if name.trim().eq_ignore_ascii_case("retry-after") {
                retry_after = parse_retry_after_header(val);
            } else if name.trim().eq_ignore_ascii_case("transfer-encoding")
                && val.to_ascii_lowercase().contains("chunked")
            {
                chunked = true;
            } else if name.trim().eq_ignore_ascii_case("content-length") {
                content_length = val.trim().parse::<usize>().ok();
            }
        }
    }

    let body_raw = &raw[hdr_end + 4..];
    let body_bytes = if chunked {
        decode_chunked_body(body_raw)?
    } else if let Some(len) = content_length {
        if body_raw.len() < len {
            return Err(AetherError::Api("truncated HTTP response body".into()));
        }
        body_raw[..len].to_vec()
    } else {
        body_raw.to_vec()
    };
    let body = String::from_utf8(body_bytes)
        .map_err(|_| AetherError::Api("non-utf8 HTTP response body".into()))?;
    Ok(FragmentedHttpReply {
        status,
        retry_after,
        body,
    })
}

async fn resolve_api_addrs(edge: Option<&str>) -> Result<Vec<std::net::SocketAddr>> {
    if let Some(ip) = edge {
        let addr: std::net::SocketAddr = format!("{ip}:443")
            .parse()
            .map_err(|_| AetherError::Api(format!("invalid API fallback edge {ip}")))?;
        return Ok(vec![addr]);
    }
    let resolved: Vec<std::net::SocketAddr> = tokio::net::lookup_host((API_HOST, 443u16))
        .await
        .map_err(|e| AetherError::Api(format!("resolve {API_HOST}: {e}")))?
        .collect();
    if resolved.is_empty() {
        return Err(AetherError::Api(format!(
            "resolve {API_HOST} returned no addresses"
        )));
    }
    Ok(resolved)
}

fn fragmented_tls_config() -> Result<std::sync::Arc<rustls::ClientConfig>> {
    static CFG: std::sync::OnceLock<std::sync::Arc<rustls::ClientConfig>> =
        std::sync::OnceLock::new();
    if let Some(cached) = CFG.get() {
        return Ok(std::sync::Arc::clone(cached));
    }
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut cfg = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .map_err(|e| AetherError::Api(format!("fragmented API TLS config: {e}")))?
    .with_root_certificates(roots)
    .with_no_client_auth();
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    let arc = std::sync::Arc::new(cfg);
    let _ = CFG.set(std::sync::Arc::clone(&arc));
    Ok(arc)
}

async fn send_fragmented_http1(
    edge: Option<&str>,
    frag_cfg: crate::fragment::FragmentConfig,
    method: &str,
    path: &str,
    bearer: Option<&str>,
    jwt: Option<&str>,
    json_body: &[u8],
) -> Result<FragmentedHttpReply> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let tls_cfg = fragmented_tls_config()?;
    let server_name = rustls_pki_types::ServerName::try_from(API_HOST.to_string())
        .map_err(|e| AetherError::Api(format!("fragmented API SNI {API_HOST}: {e}")))?;

    let addrs = resolve_api_addrs(edge).await?;
    let mut last_err = String::from("no addresses");
    let mut connected_tcp = None;
    for addr in addrs {
        match tokio::time::timeout(
            std::time::Duration::from_secs(10),
            tokio::net::TcpStream::connect(addr),
        )
        .await
        {
            Ok(Ok(tcp)) => {
                let _ = tcp.set_nodelay(true);
                connected_tcp = Some(tcp);
                break;
            }
            Ok(Err(e)) => last_err = e.to_string(),
            Err(_) => last_err = "TCP connect timeout".into(),
        }
    }
    let tcp = connected_tcp
        .ok_or_else(|| AetherError::Api(format!("fragmented API connect failed: {last_err}")))?;

    let wrapped = crate::fragment::FragmentingStream::new(tcp, frag_cfg);
    let connector = tokio_rustls::TlsConnector::from(tls_cfg);
    let mut tls = tokio::time::timeout(
        std::time::Duration::from_secs(15),
        connector.connect(server_name, wrapped),
    )
    .await
    .map_err(|_| AetherError::Api("fragmented API TLS timeout".into()))?
    .map_err(|e| AetherError::Api(format!("fragmented API TLS: {e}")))?;
    tls.get_mut().0.stop_fragmenting();

    let mut req = format!(
        "{method} {path} HTTP/1.1\r\n\
         Host: {API_HOST}\r\n\
         User-Agent: {}\r\n\
         CF-Client-Version: {}\r\n\
         Content-Type: application/json; charset=UTF-8\r\n\
         Accept: application/json\r\n\
         Connection: close\r\n\
         Content-Length: {}\r\n",
        consts::UA_REGISTER,
        consts::CF_CLIENT_VERSION,
        json_body.len()
    );
    if let Some(tok) = bearer {
        req.push_str(&format!("Authorization: Bearer {tok}\r\n"));
    }
    if let Some(j) = jwt {
        req.push_str(&format!("CF-Access-Jwt-Assertion: {j}\r\n"));
    }
    req.push_str("\r\n");

    tls.write_all(req.as_bytes())
        .await
        .map_err(|e| AetherError::Api(format!("fragmented API write headers: {e}")))?;
    tls.write_all(json_body)
        .await
        .map_err(|e| AetherError::Api(format!("fragmented API write body: {e}")))?;
    tls.flush()
        .await
        .map_err(|e| AetherError::Api(format!("fragmented API flush: {e}")))?;

    const MAX_RESPONSE_BYTES: usize = 256 * 1024;
    let mut raw = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let n = tokio::time::timeout(std::time::Duration::from_secs(15), tls.read(&mut chunk))
            .await
            .map_err(|_| AetherError::Api("fragmented API read timeout".into()))?
            .map_err(|e| AetherError::Api(format!("fragmented API read: {e}")))?;
        if n == 0 {
            break;
        }
        if raw.len() + n > MAX_RESPONSE_BYTES {
            return Err(AetherError::Api("fragmented API response too large".into()));
        }
        raw.extend_from_slice(&chunk[..n]);
    }

    parse_http1_reply(&raw)
}

/// Build the API HTTP client. When `edge` is set, DNS for the API host is pinned to
/// that Cloudflare edge IP (camouflaged, DNS-free path); SNI still follows the URL.
fn http_client(edge: Option<&str>) -> Result<reqwest::Client> {
    let mut b = reqwest::Client::builder()
        .no_proxy()
        .user_agent(consts::UA_REGISTER)
        .timeout(std::time::Duration::from_secs(20));
    if let Some(ip) = edge {
        if let Ok(addr) = format!("{ip}:443").parse::<std::net::SocketAddr>() {
            b = b.resolve(API_HOST, addr);
        }
    }
    b.build().map_err(|e| AetherError::Api(e.to_string()))
}

/// Parse a `Retry-After` header (delta-seconds form) into a Duration.
fn retry_after(resp: &reqwest::Response) -> Option<std::time::Duration> {
    resp.headers()
        .get(reqwest::header::RETRY_AFTER)?
        .to_str()
        .ok()?
        .trim()
        .parse::<u64>()
        .ok()
        .map(std::time::Duration::from_secs)
}

/// Send an API request resiliently: supports both standard HTTPS via reqwest
/// and SNI-split fragmented TLS 1.3 via BoringSSL (`FragmentingStream`).
async fn send_resilient(
    method: &str,
    path: &str,
    bearer: Option<&str>,
    jwt: Option<&str>,
    json_body: &[u8],
) -> Result<AccountData> {
    let mut targets: Vec<Option<&str>> = vec![None];
    targets.extend(API_FALLBACK_EDGES.iter().map(|e| Some(*e)));

    let url = format!("{}{path}", consts::API_URL);
    let frag_env = crate::fragment::FragmentConfig::from_env();
    let started = std::time::Instant::now();
    const MAX_TOTAL_RETRY_BUDGET: std::time::Duration = std::time::Duration::from_secs(90);
    const MAX_RETRY_AFTER: std::time::Duration = std::time::Duration::from_secs(15);
    let mut last = String::from("no attempt made");

    if !fragmented_http1_enabled() {
        for (ti, edge) in targets.iter().enumerate() {
            if started.elapsed() >= MAX_TOTAL_RETRY_BUDGET {
                break;
            }
            let client = match http_client(*edge) {
                Ok(c) => c,
                Err(e) => {
                    last = e.to_string();
                    continue;
                }
            };
            for attempt in 0u32..3 {
                if started.elapsed() >= MAX_TOTAL_RETRY_BUDGET {
                    break;
                }
                crate::session_event::mark_progress();
                let mut req = match method {
                    "PATCH" => client.patch(&url),
                    _ => client.post(&url),
                }
                .headers(base_headers())
                .body(json_body.to_vec());
                if let Some(tok) = bearer {
                    req = req.bearer_auth(tok);
                }
                if let Some(j) = jwt {
                    req = req.header("CF-Access-Jwt-Assertion", j);
                }
                match req.send().await {
                    Ok(resp) => {
                        let status = resp.status();
                        if status.as_u16() == 429 || status.is_server_error() {
                            let wait = retry_after(&resp)
                                .unwrap_or_else(|| {
                                    std::time::Duration::from_millis(500u64 << attempt)
                                })
                                .min(MAX_RETRY_AFTER);
                            last = format!("HTTP {status}");
                            crate::session_event::mark_progress();
                            tokio::time::sleep(wait).await;
                            continue;
                        }
                        let text = resp
                            .text()
                            .await
                            .map_err(|e| AetherError::Api(e.to_string()))?;
                        return parse_account_body(status.as_u16(), &text);
                    }
                    Err(e) => {
                        last = e.to_string();
                        crate::session_event::mark_progress();
                        tokio::time::sleep(std::time::Duration::from_millis(400u64 << attempt))
                            .await;
                    }
                }
            }
            if ti == 0 {
                log::warn!(
                    "[account] api.cloudflareclient.com unreachable via DNS ({last}); trying camouflaged edge fallback"
                );
            }
        }
        log::warn!(
            "[account] plain API requests failed ({last}); attempting SNI-fragmented fallback on Cloudflare edges"
        );
    }

    let frag_cfg = if frag_env.enabled {
        frag_env
    } else {
        crate::fragment::FragmentConfig::sni_default()
    };
    let frag_targets: &[Option<&str>] = if frag_env.enabled {
        &targets
    } else {
        &[
            Some("162.159.192.1"),
            Some("162.159.195.1"),
            Some("188.114.96.1"),
        ]
    };
    for (ti, edge) in frag_targets.iter().enumerate() {
        if started.elapsed() >= MAX_TOTAL_RETRY_BUDGET {
            break;
        }
        for attempt in 0u32..2 {
            if started.elapsed() >= MAX_TOTAL_RETRY_BUDGET {
                break;
            }
            crate::session_event::mark_progress();
            match send_fragmented_http1(*edge, frag_cfg, method, path, bearer, jwt, json_body).await
            {
                Ok(reply) if reply.status == 429 || reply.status >= 500 => {
                    let wait = reply
                        .retry_after
                        .unwrap_or_else(|| std::time::Duration::from_millis(500u64 << attempt))
                        .min(MAX_RETRY_AFTER);
                    last = format!("HTTP {}", reply.status);
                    crate::session_event::mark_progress();
                    tokio::time::sleep(wait).await;
                }
                Ok(reply) => return parse_account_body(reply.status, &reply.body),
                Err(e) => {
                    last = e.to_string();
                    crate::session_event::mark_progress();
                    tokio::time::sleep(std::time::Duration::from_millis(400u64 << attempt)).await;
                }
            }
        }
        if ti == 0 && frag_env.enabled {
            log::warn!("[account] fragmented DNS API call failed ({last}); trying edge fallback");
        }
    }

    Err(AetherError::Api(format!(
        "account API unreachable after retries and edge fallback: {last}"
    )))
}

fn base_headers() -> reqwest::header::HeaderMap {
    use reqwest::header::{HeaderMap, HeaderValue, CONNECTION, CONTENT_TYPE};
    let mut h = HeaderMap::new();
    h.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("application/json; charset=UTF-8"),
    );
    h.insert(CONNECTION, HeaderValue::from_static("Keep-Alive"));
    h.insert(
        "CF-Client-Version",
        HeaderValue::from_static(consts::CF_CLIENT_VERSION),
    );
    h
}

fn generate_x25519_keypair() -> ([u8; 32], String) {
    use rand::RngCore;
    // The OS generator, not the thread RNG: this is the long-lived device key,
    // and the only thing between a leaked private scalar and a forged
    // WireGuard identity is how the 32 bytes were drawn.
    let mut private = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut private);

    private[0] &= 248;
    private[31] &= 127;
    private[31] |= 64;

    let public = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(private));
    let public_b64 = base64::engine::general_purpose::STANDARD.encode(public.as_bytes());

    (private, public_b64)
}

fn random_android_serial() -> String {
    let mut s = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut s);
    hex::encode(s)
}

fn tos_timestamp() -> String {
    chrono::Local::now()
        .format("%Y-%m-%dT%H:%M:%S%.3f%:z")
        .to_string()
}

pub async fn register(
    model: &str,
    locale: &str,
    jwt: Option<&str>,
) -> Result<(AccountData, [u8; 32])> {
    let (wg_private, wg_public) = generate_x25519_keypair();

    let body = Registration {
        key: wg_public,
        install_id: String::new(),
        fcm_token: String::new(),
        tos: tos_timestamp(),
        model: model.to_string(),
        serial_number: random_android_serial(),
        os_version: String::new(),
        key_type: "curve25519".to_string(),
        tunnel_type: "wireguard".to_string(),
        locale: locale.to_string(),
    };

    let path = format!("/{}/reg", consts::API_VERSION);
    let body_bytes = serde_json::to_vec(&body).map_err(|e| AetherError::Api(e.to_string()))?;
    let account = send_resilient("POST", &path, None, jwt, &body_bytes).await?;
    Ok((account, wg_private))
}

pub async fn enroll_key(
    device_id: &str,
    token: &str,
    spki_der: &[u8],
    name: Option<&str>,
) -> Result<AccountData> {
    if device_id.is_empty()
        || !device_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(AetherError::Api(format!(
            "invalid device_id for key enrollment: {device_id:?}"
        )));
    }
    let body = DeviceUpdate {
        key: base64::engine::general_purpose::STANDARD.encode(spki_der),
        key_type: consts::KEY_TYPE_MASQUE.to_string(),
        tunnel_type: consts::TUN_TYPE_MASQUE.to_string(),
        name: name.map(|s| s.to_string()),
    };

    let path = format!("/{}/reg/{}", consts::API_VERSION, device_id);
    let body_bytes = serde_json::to_vec(&body).map_err(|e| AetherError::Api(e.to_string()))?;
    send_resilient("PATCH", &path, Some(token), None, &body_bytes).await
}

fn parse_account_body(status: u16, text: &str) -> Result<AccountData> {
    if !(200..300).contains(&status) {
        if matches!(status, 401 | 403) {
            return Err(AetherError::ApiUnauthorized(format!("HTTP {status}")));
        }
        return Err(AetherError::Api(format!(
            "upstream account API returned {status}"
        )));
    }
    let acct = serde_json::from_str::<AccountData>(text)
        .map_err(|e| AetherError::Api(format!("invalid account API response: {e}")))?;
    for (i, p) in acct.config.peers.iter().enumerate() {
        if !p.endpoint.host.is_empty() || !p.endpoint.v4.is_empty() || !p.endpoint.v6.is_empty() {
            log::info!(
                "[account] peer[{i}] endpoint host={:?} v4={:?} v6={:?}",
                p.endpoint.host,
                p.endpoint.v4,
                p.endpoint.v6
            );
        }
    }
    Ok(acct)
}

fn extract_wg_peer(reg: &AccountData) -> Result<[u8; 32]> {
    if reg.config.peers.is_empty() {
        return Err(AetherError::Api("no peers in registration response".into()));
    }
    let peer_b64 = &reg.config.peers[0].public_key;
    let decoded = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, peer_b64)
        .map_err(|e| AetherError::Api(format!("decode peer pubkey: {e}")))?;
    if decoded.len() != 32 {
        return Err(AetherError::Api("invalid peer pubkey length".into()));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&decoded);
    Ok(arr)
}

pub async fn provision_wg(model: &str, locale: &str, jwt: Option<&str>) -> Result<Identity> {
    let (reg, wg_private) = register(model, locale, jwt).await?;
    if reg.token.is_empty() {
        return Err(AetherError::Api("registration returned empty token".into()));
    }

    let wg_peer_public = extract_wg_peer(&reg)?;

    let mut client_id_arr = [0u8; 3];
    if !reg.config.client_id.is_empty() {
        log::debug!("[account] received client_id from API");
        if let Ok(decoded) = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &reg.config.client_id,
        ) {
            if decoded.len() == 3 {
                client_id_arr.copy_from_slice(&decoded);
                log::debug!("[account] decoded client_id: {:02x?}", client_id_arr);
            } else {
                log::warn!(
                    "[account] client_id decoded but wrong length: {}",
                    decoded.len()
                );
            }
        } else {
            log::warn!("[account] failed to decode client_id base64");
        }
    } else {
        log::warn!("[account] API response has empty client_id, using zeros");
    }

    Ok(Identity {
        device_id: reg.id,
        access_token: reg.token,
        cert_pem: Vec::new(),
        key_pem: Vec::new(),
        ipv4: reg.config.interface.addresses.v4,
        ipv6: reg.config.interface.addresses.v6,
        wg_private_key: wg_private,
        wg_peer_public_key: wg_peer_public,
        client_id: client_id_arr,
        masque_endpoint: None,
    })
}

/// Check if an X.509 client certificate is expired or expiring within 24 hours.
pub fn is_cert_expired(cert_pem: &[u8]) -> bool {
    let Ok(cert) = X509::from_pem(cert_pem) else {
        return true;
    };
    let Ok(threshold) = Asn1Time::days_from_now(1) else {
        return true;
    };
    !matches!(
        cert.not_after().compare(&threshold),
        Ok(std::cmp::Ordering::Greater)
    )
}

pub async fn ensure_masque_enrolled(
    identity: &Identity,
) -> Result<(Vec<u8>, Vec<u8>, Option<String>)> {
    if !identity.cert_pem.is_empty()
        && !identity.key_pem.is_empty()
        && !is_cert_expired(&identity.cert_pem)
    {
        return Ok((
            identity.cert_pem.clone(),
            identity.key_pem.clone(),
            identity.masque_endpoint.clone(),
        ));
    }

    if !identity.cert_pem.is_empty() && is_cert_expired(&identity.cert_pem) {
        log::info!(
            "[+] existing MASQUE certificate for device {} is expired or expiring; re-enrolling",
            identity.device_id
        );
    } else {
        log::info!("[+] enrolling MASQUE key for device {}", identity.device_id);
    }
    let keypair = generate_masque_keypair()?;
    let acct = enroll_key(
        &identity.device_id,
        &identity.access_token,
        &keypair.spki_der,
        None,
    )
    .await?;
    let endpoint = masque_endpoint_from(&acct);
    log::info!("[+] MASQUE key enrolled (endpoint={endpoint:?})");
    Ok((keypair.cert_pem.clone(), keypair.key_pem.clone(), endpoint))
}

/// Extract the MASQUE data-plane endpoint (host:443) from a registration/enroll
/// response's first peer. The API returns `endpoint.v4` like "162.159.198.2:0";
/// the MASQUE QUIC port is 443, so normalize it.
fn masque_endpoint_from(acct: &AccountData) -> Option<String> {
    let ep = &acct.config.peers.first()?.endpoint;
    let v4 = ep.v4.trim();
    if !v4.is_empty() {
        let host = v4.rsplit_once(':').map(|(h, _)| h).unwrap_or(v4);
        if !host.is_empty() {
            return Some(format!("{host}:443"));
        }
    }
    let v6 = ep.v6.trim();
    if !v6.is_empty() {
        let host = if let Some(rest) = v6.strip_prefix('[') {
            rest.split(']').next().unwrap_or("")
        } else {
            v6
        };
        if !host.is_empty() {
            return Some(format!("[{host}]:443"));
        }
    }
    None
}

impl Identity {
    /// The tunnel's inner IPv4 address, parsed.
    ///
    /// Six call sites used to parse `identity.ipv4` themselves and paper over a
    /// failure - four with `unwrap_or(172.16.0.2)`, one with `.ok()` that turned
    /// it into a silent `None`, one with an `Other("invalid ipv4")` that said
    /// nothing about which identity or which value. An account record whose
    /// `ipv4` was empty, truncated or written by a different provisioner therefore
    /// produced a *plausible* tunnel: it came up, the peer dropped every packet
    /// that did not match, and no log line said the identity was unreadable. A
    /// config value that cannot be parsed is an error, not a chance to guess.
    pub fn tunnel_ipv4(&self) -> Result<std::net::Ipv4Addr> {
        self.ipv4.trim().parse::<std::net::Ipv4Addr>().map_err(|_| {
            AetherError::Config(format!(
                "account config carries an unusable tunnel IPv4 ({:?}); re-provision rather than guess",
                self.ipv4
            ))
        })
    }

    pub fn private_key_bytes(&self) -> Result<[u8; 32]> {
        Ok(self.wg_private_key)
    }

    pub fn peer_public_key_bytes(&self) -> Result<[u8; 32]> {
        Ok(self.wg_peer_public_key)
    }

    pub fn has_masque_credentials(&self) -> bool {
        !self.cert_pem.is_empty() && !self.key_pem.is_empty() && !is_cert_expired(&self.cert_pem)
    }

    pub fn capability(&self) -> IdentityCapability {
        if self.has_masque_credentials() {
            IdentityCapability::MasqueReady
        } else {
            IdentityCapability::WireGuardOnly
        }
    }

    pub fn can_run_masque(&self) -> bool {
        matches!(self.capability(), IdentityCapability::MasqueReady)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_content_length_http1_reply() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 15\r\n\r\n{\"id\":\"dev-01\"}ignored";
        let reply = parse_http1_reply(raw).unwrap();
        assert_eq!(reply.status, 200);
        assert_eq!(reply.body, "{\"id\":\"dev-01\"}");
    }

    #[test]
    fn parses_chunked_http1_reply_and_retry_after() {
        let raw = b"HTTP/1.1 429 Too Many Requests\r\nRetry-After: 7\r\nTransfer-Encoding: chunked\r\n\r\n7\r\n{\"a\":1}\r\n0\r\n\r\n";
        let reply = parse_http1_reply(raw).unwrap();
        assert_eq!(reply.status, 429);
        assert_eq!(reply.retry_after, Some(std::time::Duration::from_secs(7)));
        assert_eq!(reply.body, "{\"a\":1}");
    }

    #[test]
    fn maps_401_and_403_to_unauthorized_error() {
        assert!(matches!(
            parse_account_body(401, "{}"),
            Err(AetherError::ApiUnauthorized(_))
        ));
        assert!(matches!(
            parse_account_body(403, "{}"),
            Err(AetherError::ApiUnauthorized(_))
        ));
    }
}
