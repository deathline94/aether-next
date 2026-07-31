use octets::{Octets, OctetsMut};
use quiche::h3;

use crate::consts;
use crate::error::{AetherError, Result};

pub const CAPSULE_ADDRESS_ASSIGN: u64 = 0x01;
pub const CAPSULE_ADDRESS_REQUEST: u64 = 0x02;
pub const CAPSULE_ROUTE_ADVERTISEMENT: u64 = 0x03;
pub const CAPSULE_DATAGRAM: u64 = 0x00;

#[derive(Debug, Clone)]
pub struct AssignedAddress {
    pub ip_version: u8,
    pub address: Vec<u8>,
    pub prefix_len: u8,
}

#[derive(Debug, Clone)]
pub struct RouteAdvertisement {
    pub ip_version: u8,
    pub start: Vec<u8>,
    pub end: Vec<u8>,
    pub protocol: u8,
}

#[derive(Debug, Clone)]
pub enum Capsule {
    AddressAssign(Vec<AssignedAddress>),
    AddressRequest,
    Datagram(Vec<u8>),
    RouteAdvertisement(Vec<RouteAdvertisement>),
    Unknown,
}

/// Request-header recipe for the H3 CONNECT-IP request.
///
/// The engine's working H2 path uses Cloudflare's custom `cf-connect-proto`
/// header on a classic CONNECT rather than the RFC 9484 extended-CONNECT
/// `:protocol` pseudo-header. These modes let us A/B the two on H3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum H3HeaderMode {
    /// Mirror the working H2 recipe: classic CONNECT + `cf-connect-proto`/`pq-enabled`.
    Cf,
    /// RFC 9484 extended CONNECT: `:protocol` + `:scheme`/`:path` + `capsule-protocol`.
    Standard,
    /// Superset of both (kitchen sink for the probe matrix).
    Both,
}

impl H3HeaderMode {
    /// Resolve from `AETHER_MASQUE_H3_HEADERS` (default: `standard`).
    pub fn from_env() -> Self {
        match crate::runtime_env::var("AETHER_MASQUE_H3_HEADERS")
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase()
            .as_str()
        {
            "cf" => H3HeaderMode::Cf,
            "both" => H3HeaderMode::Both,
            // Default: Standard = clean RFC 9484 extended CONNECT (:protocol
            // cf-connect-ip + :scheme/:authority/:path). Proven live to reach 200 +
            // data-plane on the MASQUE VIP. The previous `Both` default piled the
            // legacy cf-connect-proto/pq-enabled headers on top, which some edges
            // reject with 400 (observed on 162.159.198.2) -> H3 could not connect.
            _ => H3HeaderMode::Standard,
        }
    }
}

/// How the H3 data plane tunnels IP packets.
///
/// RFC 9484 prefers HTTP/3 DATAGRAMs (QUIC DATAGRAM frames). When the peer does
/// not negotiate H3 DATAGRAM (SETTINGS_H3_DATAGRAM), RFC 9297 permits a fallback
/// of carrying DATAGRAM *capsules* on the request stream (this is how the H2
/// path works). `Auto` picks per negotiation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum H3DgramMode {
    Quic,
    Capsule,
    Auto,
}

impl H3DgramMode {
    /// Resolve from `AETHER_MASQUE_H3_DGRAM` (default: `auto`).
    pub fn from_env() -> Self {
        Self::parse(crate::runtime_env::var("AETHER_MASQUE_H3_DGRAM").as_deref())
    }

    pub fn parse(v: Option<&str>) -> Self {
        match v.unwrap_or("").trim().to_ascii_lowercase().as_str() {
            "quic" | "datagram" | "dgram" => H3DgramMode::Quic,
            "capsule" | "stream" => H3DgramMode::Capsule,
            _ => H3DgramMode::Auto,
        }
    }

    /// Whether to tunnel IP as DATAGRAM capsules on the stream (vs QUIC DATAGRAM).
    pub fn use_capsule(self, dgram_enabled_by_peer: bool) -> bool {
        match self {
            H3DgramMode::Quic => false,
            H3DgramMode::Capsule => true,
            H3DgramMode::Auto => !dgram_enabled_by_peer,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            H3DgramMode::Quic => "quic",
            H3DgramMode::Capsule => "capsule",
            H3DgramMode::Auto => "auto",
        }
    }
}

pub fn connect_ip_request(authority: &str, path: &str) -> Vec<h3::Header> {
    connect_ip_request_mode(authority, path, H3HeaderMode::from_env())
}

/// Build the CONNECT-IP request headers for a given recipe (pure; used by tests).
pub fn connect_ip_request_mode(authority: &str, path: &str, mode: H3HeaderMode) -> Vec<h3::Header> {
    let want_ext = matches!(mode, H3HeaderMode::Standard | H3HeaderMode::Both);
    let want_cf = matches!(mode, H3HeaderMode::Cf | H3HeaderMode::Both);

    let mut h = vec![h3::Header::new(b":method", b"CONNECT")];
    if want_ext {
        // RFC 9220/9484 extended CONNECT requires :protocol, :scheme, :path.
        // Cloudflare's MASQUE H3 requires `:protocol: cf-connect-ip` (its custom
        // value, NOT the RFC 9484 `connect-ip` which Cloudflare answers with 403).
        // Proven live: cf-connect-ip -> 200 + data-plane; connect-ip -> 403.
        // Override via env for diagnostics.
        let proto = crate::runtime_env::var("AETHER_MASQUE_H3_PROTOCOL")
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| consts::CF_CONNECT_PROTOCOL.to_string());
        h.push(h3::Header::new(b":protocol", proto.as_bytes()));
        h.push(h3::Header::new(b":scheme", b"https"));
        h.push(h3::Header::new(b":authority", authority.as_bytes()));
        h.push(h3::Header::new(b":path", path.as_bytes()));
    } else {
        // Classic CONNECT authority-form: only :method + :authority (matches H2).
        h.push(h3::Header::new(b":authority", authority.as_bytes()));
    }
    h.push(h3::Header::new(b"user-agent", b""));
    if want_cf {
        h.push(h3::Header::new(
            consts::CF_CONNECT_PROTO_HEADER.as_bytes(),
            consts::CF_CONNECT_PROTOCOL.as_bytes(),
        ));
        h.push(h3::Header::new(
            consts::CF_PQ_ENABLED_HEADER.as_bytes(),
            consts::CF_PQ_ENABLED_VALUE.as_bytes(),
        ));
    }
    if want_ext {
        h.push(h3::Header::new(b"capsule-protocol", b"?1"));
    }
    h
}

pub fn quarter_stream_id(stream_id: u64) -> u64 {
    stream_id / 4
}

pub fn encode_ip_datagram(stream_id: u64, ip_packet: &[u8]) -> Result<Vec<u8>> {
    let qsid = quarter_stream_id(stream_id);
    let ctx = consts::CONNECT_IP_CONTEXT_ID;

    let cap = varint_len(qsid) + varint_len(ctx) + ip_packet.len();
    let mut out = vec![0u8; cap];

    {
        let mut b = OctetsMut::with_slice(&mut out);
        b.put_varint(qsid).map_err(oct)?;
        b.put_varint(ctx).map_err(oct)?;
        b.put_bytes(ip_packet).map_err(oct)?;
    }

    Ok(out)
}

pub fn decode_ip_datagram(datagram: &[u8], expect_stream_id: u64) -> Result<Option<Vec<u8>>> {
    let mut b = Octets::with_slice(datagram);

    let qsid = b.get_varint().map_err(oct)?;
    if qsid != quarter_stream_id(expect_stream_id) {
        return Ok(None);
    }

    let ctx = b.get_varint().map_err(oct)?;
    if ctx != consts::CONNECT_IP_CONTEXT_ID {
        return Ok(None);
    }

    let rest = b.cap();
    let payload = b.get_bytes(rest).map_err(oct)?;
    Ok(Some(payload.to_vec()))
}

pub fn encode_capsule(kind: u64, value: &[u8]) -> Vec<u8> {
    let cap = varint_len(kind) + varint_len(value.len() as u64) + value.len();
    let mut out = vec![0u8; cap];
    {
        let mut b = OctetsMut::with_slice(&mut out);
        let _ = b.put_varint(kind);
        let _ = b.put_varint(value.len() as u64);
        let _ = b.put_bytes(value);
    }
    out
}

pub fn encode_datagram_capsule(ip_packet: &[u8]) -> Vec<u8> {
    encode_capsule(CAPSULE_DATAGRAM, ip_packet)
}

pub struct CapsuleParser {
    buf: Vec<u8>,
}

impl CapsuleParser {
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    pub fn push(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    pub fn next(&mut self) -> Result<Option<Capsule>> {
        let mut b = Octets::with_slice(&self.buf);

        let kind = match b.get_varint() {
            Ok(v) => v,
            Err(_) => return Ok(None),
        };
        let len = match b.get_varint() {
            Ok(v) => v as usize,
            Err(_) => return Ok(None),
        };
        // Cap absurd lengths so a corrupt stream cannot stall forever.
        if len > 4 * 1024 * 1024 {
            self.buf.clear();
            return Err(AetherError::Capsule(format!("capsule too large: {len}")));
        }
        if b.cap() < len {
            return Ok(None);
        }

        let value = match b.get_bytes(len) {
            Ok(v) => v.to_vec(),
            Err(e) => {
                self.buf.clear();
                return Err(oct(e));
            }
        };
        let consumed = b.off();
        self.buf.drain(0..consumed);

        let capsule = match kind {
            CAPSULE_ADDRESS_ASSIGN => match parse_address_assign(&value) {
                Ok(a) => Capsule::AddressAssign(a),
                Err(e) => {
                    // Skip bad capsule; do not leave partial state forever.
                    return Err(e);
                }
            },
            CAPSULE_ADDRESS_REQUEST => Capsule::AddressRequest,
            CAPSULE_ROUTE_ADVERTISEMENT => {
                Capsule::RouteAdvertisement(parse_route_advertisement(&value)?)
            }
            CAPSULE_DATAGRAM => Capsule::Datagram(value),
            _ => Capsule::Unknown,
        };

        Ok(Some(capsule))
    }
}

impl Default for CapsuleParser {
    fn default() -> Self {
        Self::new()
    }
}

fn parse_address_assign(value: &[u8]) -> Result<Vec<AssignedAddress>> {
    let mut b = Octets::with_slice(value);
    let mut out = Vec::new();

    while b.cap() > 0 {
        // request id: consumed to advance the buffer, not otherwise used.
        let _ = b.get_varint().map_err(oct)?;
        let ip_version = b.get_u8().map_err(oct)?;
        let addr_len = match ip_version {
            4 => 4,
            6 => 16,
            _ => return Err(AetherError::Capsule(format!("bad ip version {ip_version}"))),
        };
        let address = b.get_bytes(addr_len).map_err(oct)?.to_vec();
        let prefix_len = b.get_u8().map_err(oct)?;

        out.push(AssignedAddress {
            ip_version,
            address,
            prefix_len,
        });
    }

    Ok(out)
}

fn parse_route_advertisement(value: &[u8]) -> Result<Vec<RouteAdvertisement>> {
    let mut b = Octets::with_slice(value);
    let mut out = Vec::new();

    while b.cap() > 0 {
        let ip_version = b.get_u8().map_err(oct)?;
        let addr_len = match ip_version {
            4 => 4,
            6 => 16,
            _ => return Err(AetherError::Capsule(format!("bad ip version {ip_version}"))),
        };
        let start = b.get_bytes(addr_len).map_err(oct)?.to_vec();
        let end = b.get_bytes(addr_len).map_err(oct)?.to_vec();
        let protocol = b.get_u8().map_err(oct)?;

        out.push(RouteAdvertisement {
            ip_version,
            start,
            end,
            protocol,
        });
    }

    Ok(out)
}

fn varint_len(v: u64) -> usize {
    if v < 64 {
        1
    } else if v < 16384 {
        2
    } else if v < 1_073_741_824 {
        4
    } else {
        8
    }
}

fn oct(e: octets::BufferTooShortError) -> AetherError {
    AetherError::Capsule(e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quarter_stream_id_divides_by_four() {
        assert_eq!(quarter_stream_id(0), 0);
        assert_eq!(quarter_stream_id(4), 1);
        assert_eq!(quarter_stream_id(12), 3);
    }

    #[test]
    fn ip_datagram_roundtrip() {
        let stream = 4u64;
        let pkt = vec![0x45, 0x00, 0x00, 0x14, 0x00, 0x01, 0x00, 0x00, 0x40, 0x01];
        let enc = encode_ip_datagram(stream, &pkt).expect("encode");
        let dec = decode_ip_datagram(&enc, stream).expect("decode");
        assert_eq!(dec, Some(pkt));
    }

    #[test]
    fn ip_datagram_wrong_stream_ignored() {
        let enc = encode_ip_datagram(4, b"abc").expect("encode");
        let dec = decode_ip_datagram(&enc, 8).expect("decode");
        assert!(dec.is_none());
    }

    #[test]
    fn capsule_datagram_encode_nonempty() {
        let c = encode_datagram_capsule(b"hello");
        assert!(!c.is_empty());
    }

    use quiche::h3::NameValue;

    fn header_value(hs: &[h3::Header], name: &[u8]) -> Option<Vec<u8>> {
        hs.iter().find(|h| h.name() == name).map(|h| h.value().to_vec())
    }

    #[test]
    fn h3_headers_cf_mirrors_h2_recipe() {
        let hs = connect_ip_request_mode("cloudflareaccess.com", "/", H3HeaderMode::Cf);
        assert_eq!(header_value(&hs, b":method").as_deref(), Some(&b"CONNECT"[..]));
        assert_eq!(header_value(&hs, b":authority").as_deref(), Some(&b"cloudflareaccess.com"[..]));
        assert_eq!(header_value(&hs, b"cf-connect-proto").as_deref(), Some(&b"cf-connect-ip"[..]));
        assert_eq!(header_value(&hs, b"pq-enabled").as_deref(), Some(&b"false"[..]));
        // Classic CONNECT: no extended-CONNECT pseudo-headers.
        assert!(header_value(&hs, b":protocol").is_none());
        assert!(header_value(&hs, b":path").is_none());
        assert!(header_value(&hs, b"capsule-protocol").is_none());
    }

    #[test]
    fn h3_headers_standard_is_extended_connect() {
        let hs = connect_ip_request_mode("cloudflareaccess.com", "/", H3HeaderMode::Standard);
        assert_eq!(header_value(&hs, b":protocol").as_deref(), Some(&b"cf-connect-ip"[..]));
        assert_eq!(header_value(&hs, b":scheme").as_deref(), Some(&b"https"[..]));
        assert_eq!(header_value(&hs, b":path").as_deref(), Some(&b"/"[..]));
        assert_eq!(header_value(&hs, b"capsule-protocol").as_deref(), Some(&b"?1"[..]));
        assert!(header_value(&hs, b"cf-connect-proto").is_none());
    }

    #[test]
    fn h3_headers_both_is_superset() {
        let hs = connect_ip_request_mode("cloudflareaccess.com", "/", H3HeaderMode::Both);
        assert!(header_value(&hs, b":protocol").is_some());
        assert!(header_value(&hs, b"cf-connect-proto").is_some());
        assert!(header_value(&hs, b"capsule-protocol").is_some());
    }

    #[test]
    fn datagram_wrong_context_id_ignored() {
        let sid = 4u64;
        let qsid = quarter_stream_id(sid);
        let mut buf = vec![0u8; 32];
        let n = {
            let mut b = OctetsMut::with_slice(&mut buf);
            b.put_varint(qsid).unwrap();
            b.put_varint(1).unwrap(); // context id 1 != CONNECT_IP_CONTEXT_ID (0)
            b.put_bytes(b"xy").unwrap();
            b.off()
        };
        let dec = decode_ip_datagram(&buf[..n], sid).expect("decode");
        assert!(dec.is_none());
    }

    #[test]
    fn address_assign_capsule_parses() {
        let mut value = vec![0u8; 16];
        let n = {
            let mut b = OctetsMut::with_slice(&mut value);
            b.put_varint(7).unwrap(); // request id
            b.put_u8(4).unwrap(); // ipv4
            b.put_bytes(&[10, 0, 0, 2]).unwrap();
            b.put_u8(32).unwrap(); // prefix
            b.off()
        };
        let cap = encode_capsule(CAPSULE_ADDRESS_ASSIGN, &value[..n]);
        let mut p = CapsuleParser::new();
        p.push(&cap);
        match p.next() {
            Ok(Some(Capsule::AddressAssign(a))) => {
                assert_eq!(a.len(), 1);
                assert_eq!(a[0].ip_version, 4);
                assert_eq!(a[0].address, vec![10, 0, 0, 2]);
                assert_eq!(a[0].prefix_len, 32);
            }
            other => panic!("expected AddressAssign, got {other:?}"),
        }
    }

    #[test]
    fn partial_capsule_needs_more_data() {
        let mut p = CapsuleParser::new();
        p.push(&[0x01]); // capsule type varint only; length + value missing
        assert!(matches!(p.next(), Ok(None)));
    }

    #[test]
    fn h3_dgram_mode_parse_and_selection() {
        assert_eq!(H3DgramMode::parse(Some("quic")), H3DgramMode::Quic);
        assert_eq!(H3DgramMode::parse(Some("capsule")), H3DgramMode::Capsule);
        assert_eq!(H3DgramMode::parse(Some("")), H3DgramMode::Auto);
        assert_eq!(H3DgramMode::parse(None), H3DgramMode::Auto);
        // Auto follows negotiation; explicit modes are fixed.
        assert!(H3DgramMode::Auto.use_capsule(false));
        assert!(!H3DgramMode::Auto.use_capsule(true));
        assert!(H3DgramMode::Capsule.use_capsule(true));
        assert!(!H3DgramMode::Quic.use_capsule(false));
    }

    #[test]
    fn address_assign_v6_parses() {
        let mut value = vec![0u8; 32];
        let n = {
            let mut b = OctetsMut::with_slice(&mut value);
            b.put_varint(1).unwrap();
            b.put_u8(6).unwrap();
            b.put_bytes(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]).unwrap();
            b.put_u8(128).unwrap();
            b.off()
        };
        let cap = encode_capsule(CAPSULE_ADDRESS_ASSIGN, &value[..n]);
        let mut p = CapsuleParser::new();
        p.push(&cap);
        match p.next() {
            Ok(Some(Capsule::AddressAssign(a))) => {
                assert_eq!(a.len(), 1);
                assert_eq!(a[0].ip_version, 6);
                assert_eq!(a[0].address.len(), 16);
                assert_eq!(a[0].prefix_len, 128);
            }
            other => panic!("expected AddressAssign v6, got {other:?}"),
        }
    }

    #[test]
    fn route_advertisement_parses() {
        let mut value = vec![0u8; 32];
        let n = {
            let mut b = OctetsMut::with_slice(&mut value);
            b.put_u8(4).unwrap();
            b.put_bytes(&[10, 0, 0, 0]).unwrap();
            b.put_bytes(&[10, 0, 0, 255]).unwrap();
            b.put_u8(17).unwrap();
            b.off()
        };
        let cap = encode_capsule(CAPSULE_ROUTE_ADVERTISEMENT, &value[..n]);
        let mut p = CapsuleParser::new();
        p.push(&cap);
        match p.next() {
            Ok(Some(Capsule::RouteAdvertisement(r))) => {
                assert_eq!(r.len(), 1);
                assert_eq!(r[0].ip_version, 4);
                assert_eq!(r[0].protocol, 17);
            }
            other => panic!("expected RouteAdvertisement, got {other:?}"),
        }
    }

    #[test]
    fn oversized_capsule_rejected() {
        let mut hdr = vec![0u8; 8];
        let n = {
            let mut b = OctetsMut::with_slice(&mut hdr);
            b.put_varint(CAPSULE_DATAGRAM).unwrap();
            b.put_varint(5_000_000).unwrap(); // claimed length exceeds the 4 MiB cap
            b.off()
        };
        let mut p = CapsuleParser::new();
        p.push(&hdr[..n]);
        assert!(p.next().is_err());
    }

    #[test]
    fn datagram_short_input_no_panic() {
        let r = decode_ip_datagram(&[0x00], 4);
        assert!(r.is_err() || matches!(r, Ok(None)));
    }

    #[test]
    fn datagram_large_payload_roundtrips() {
        let big = vec![0xABu8; 4096];
        let enc = encode_ip_datagram(4, &big).expect("encode");
        let dec = decode_ip_datagram(&enc, 4).expect("decode");
        assert_eq!(dec, Some(big));
    }
}
