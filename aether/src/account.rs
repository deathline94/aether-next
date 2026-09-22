use base64::Engine;
use boring::asn1::Asn1Time;
use boring::bn::BigNum;
use boring::ec::{EcGroup, EcKey};
use boring::hash::MessageDigest;
use boring::nid::Nid;
use boring::pkey::PKey;
use boring::x509::{X509Builder, X509NameBuilder};
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
    // L5 fix: widen the 1-day validity slightly for clock-skew tolerance while
    // keeping the client certificate short-lived.
    let not_after = Asn1Time::days_from_now(7).map_err(|e| AetherError::Tls(e.to_string()))?;
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

/// Build the API HTTP client. When `edge` is set, DNS for the API host is pinned to
/// that Cloudflare edge IP (camouflaged, DNS-free path); SNI still follows the URL.
fn http_client(edge: Option<&str>) -> Result<reqwest::Client> {
    let mut b = reqwest::Client::builder()
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

/// Send an API request resiliently: exponential backoff on transient errors and
/// 429/5xx (honoring Retry-After), then a camouflaged fallback to direct Cloudflare
/// edge IPs (no DNS) when `api.cloudflareclient.com` is blocked or poisoned. `build`
/// reconstructs the request from the supplied client on each attempt.
async fn send_resilient(
    build: impl Fn(&reqwest::Client) -> reqwest::RequestBuilder,
) -> Result<reqwest::Response> {
    // Attempt targets: normal DNS first, then each camouflaged edge IP.
    let mut targets: Vec<Option<&str>> = vec![None];
    targets.extend(API_FALLBACK_EDGES.iter().map(|e| Some(*e)));

    let mut last = String::from("no attempt made");
    for (ti, edge) in targets.iter().enumerate() {
        let client = match http_client(*edge) {
            Ok(c) => c,
            Err(e) => {
                last = e.to_string();
                continue;
            }
        };
        for attempt in 0u32..3 {
            match build(&client).send().await {
                Ok(resp) => {
                    let status = resp.status();
                    if status.as_u16() == 429 || status.is_server_error() {
                        let wait = retry_after(&resp)
                            .unwrap_or_else(|| std::time::Duration::from_millis(500u64 << attempt));
                        // The header is server-supplied and this loop runs while the
                        // provision lock is held: an absurd `Retry-After` wedged
                        // provisioning with the UI parked on `identity` and every
                        // other caller waiting on the same lock.
                        const MAX_RETRY_AFTER: std::time::Duration =
                            std::time::Duration::from_secs(30);
                        let wait = if wait > MAX_RETRY_AFTER {
                            log::warn!(
                                "[provision] server asked to wait {}s; capping at {}s",
                                wait.as_secs(),
                                MAX_RETRY_AFTER.as_secs()
                            );
                            MAX_RETRY_AFTER
                        } else {
                            wait
                        };
                        last = format!("HTTP {status}");
                        tokio::time::sleep(wait).await;
                        continue;
                    }
                    return Ok(resp);
                }
                Err(e) => {
                    last = e.to_string();
                    tokio::time::sleep(std::time::Duration::from_millis(400u64 << attempt)).await;
                }
            }
        }
        if ti == 0 {
            log::warn!(
                "[account] api.cloudflareclient.com unreachable via DNS ({last}); trying camouflaged edge fallback"
            );
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

    let url = format!("{}/{}/reg", consts::API_URL, consts::API_VERSION);
    let resp = send_resilient(|client| {
        let mut req = client.post(&url).headers(base_headers()).json(&body);
        if let Some(jwt) = jwt {
            req = req.header("CF-Access-Jwt-Assertion", jwt);
        }
        req
    })
    .await?;
    let account = parse_account(resp).await?;
    Ok((account, wg_private))
}

pub async fn enroll_key(
    device_id: &str,
    token: &str,
    spki_der: &[u8],
    name: Option<&str>,
) -> Result<AccountData> {
    let body = DeviceUpdate {
        key: base64::engine::general_purpose::STANDARD.encode(spki_der),
        key_type: consts::KEY_TYPE_MASQUE.to_string(),
        tunnel_type: consts::TUN_TYPE_MASQUE.to_string(),
        name: name.map(|s| s.to_string()),
    };

    let url = format!(
        "{}/{}/reg/{}",
        consts::API_URL,
        consts::API_VERSION,
        device_id
    );
    let resp = send_resilient(|client| {
        client
            .patch(&url)
            .headers(base_headers())
            .bearer_auth(token)
            .json(&body)
    })
    .await?;

    parse_account(resp).await
}

async fn parse_account(resp: reqwest::Response) -> Result<AccountData> {
    let status = resp.status();
    let text = resp
        .text()
        .await
        .map_err(|e| AetherError::Api(e.to_string()))?;

    if !status.is_success() {
        return Err(AetherError::Api(format!(
            "upstream account API returned {status}"
        )));
    }
    let acct = serde_json::from_str::<AccountData>(&text)
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

pub async fn ensure_masque_enrolled(
    identity: &Identity,
) -> Result<(Vec<u8>, Vec<u8>, Option<String>)> {
    if !identity.cert_pem.is_empty() && !identity.key_pem.is_empty() {
        return Ok((
            identity.cert_pem.clone(),
            identity.key_pem.clone(),
            identity.masque_endpoint.clone(),
        ));
    }

    log::info!("[+] enrolling MASQUE key for device {}", identity.device_id);
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
    Ok((keypair.cert_pem, keypair.key_pem, endpoint))
}

/// Extract the MASQUE data-plane endpoint (host:443) from a registration/enroll
/// response's first peer. The API returns `endpoint.v4` like "162.159.198.2:0";
/// the MASQUE QUIC port is 443, so normalize it.
fn masque_endpoint_from(acct: &AccountData) -> Option<String> {
    let ep = acct.config.peers.first()?.endpoint.v4.trim();
    if ep.is_empty() {
        return None;
    }
    let host = ep.rsplit_once(':').map(|(h, _)| h).unwrap_or(ep);
    if host.is_empty() {
        return None;
    }
    Some(format!("{host}:443"))
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
        !self.cert_pem.is_empty() && !self.key_pem.is_empty()
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
