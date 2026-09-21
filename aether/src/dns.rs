use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::time::timeout;

use crate::error::{AetherError, Result};

pub const BOOTSTRAP_DNS: &[&str] = &["1.1.1.1:53", "1.0.0.1:53", "8.8.8.8:53"];
pub const ECH_HOSTS: &[&str] = &["cloudflare-ech.com", "crypto.cloudflare.com"];

const RR_HTTPS: u16 = 65;
const SVCPARAM_ECH: u16 = 5;

pub async fn fetch_ech_config() -> Result<Vec<u8>> {
    for host in ECH_HOSTS {
        for server in BOOTSTRAP_DNS {
            let addr: SocketAddr = match server.parse() {
                Ok(a) => a,
                Err(_) => continue,
            };
            match query_ech(addr, host).await {
                Ok(ech) if !ech.is_empty() => {
                    log::info!("fetched ECHConfigList ({} bytes) for {host} via {server}", ech.len());
                    return Ok(ech);
                }
                Ok(_) => {}
                Err(e) => log::debug!("ech bootstrap {host}@{server} failed: {e}"),
            }
        }
    }
    Err(AetherError::Ech("no ECHConfigList resolved".into()))
}

async fn query_ech(server: SocketAddr, host: &str) -> Result<Vec<u8>> {
    let bind = if server.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
    let sock = UdpSocket::bind(bind).await?;
    sock.connect(server).await?;

    let (qid, query) = build_query(host, RR_HTTPS);
    sock.send(&query).await?;

    let mut buf = [0u8; 4096];
    let n = timeout(Duration::from_secs(3), sock.recv(&mut buf))
        .await
        .map_err(|_| AetherError::Ech("dns timeout".into()))??;

    parse_https_ech(&buf[..n], qid, host).ok_or_else(|| AetherError::Ech("no ech svcparam".into()))
}

fn build_query(name: &str, qtype: u16) -> (u16, Vec<u8>) {
    let mut q = Vec::with_capacity(32 + name.len());
    let id: u16 = rand::random();
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&[0x01, 0x00]);
    q.extend_from_slice(&[0x00, 0x01]);
    q.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    for label in name.split('.') {
        if label.is_empty() {
            continue;
        }
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0x00);
    q.extend_from_slice(&qtype.to_be_bytes());
    q.extend_from_slice(&[0x00, 0x01]);
    (id, q)
}

/// Read the HTTPS RR and pull out the `ech` SvcParam.
///
/// The reply is authenticated against the request — transaction id, the echoed
/// question name and type, `QR`, and a `TC` refusal. Without those checks any
/// off-path UDP packet on the ephemeral local port (the socket *is* connected to
/// the resolver, but a forged reply from the resolver itself, or a response to a
/// stale query, still matches) decided which ECH public key every later
/// ClientHello was encrypted to, which is the whole point of ECH.
fn parse_https_ech(msg: &[u8], qid: u16, name: &str) -> Option<Vec<u8>> {
    if msg.len() < 12 {
        return None;
    }
    if u16::from_be_bytes([msg[0], msg[1]]) != qid {
        return None;
    }
    let flags = u16::from_be_bytes([msg[2], msg[3]]);
    let qr = flags & 0x8000 != 0;
    let opcode = (flags >> 11) & 0x0f;
    let tc = flags & 0x0200 != 0;
    if !qr || opcode != 0 {
        return None;
    }
    // A truncated answer may carry a partial ECHConfig; adopting it would break
    // (or silently weaken) every handshake that followed.
    if tc {
        return None;
    }
    let rcode = flags & 0x000f;
    if rcode != 0 {
        return None;
    }

    let qd = u16::from_be_bytes([msg[4], msg[5]]) as usize;
    let an = u16::from_be_bytes([msg[6], msg[7]]) as usize;
    let mut pos = 12;

    if qd != 1 {
        return None;
    }
    for _ in 0..qd {
        let asked = read_name(msg, pos)?;
        if !asked.eq_ignore_ascii_case(name) {
            return None;
        }
        pos = skip_name(msg, pos)?;
        if pos + 4 > msg.len() {
            return None;
        }
        let qtype = u16::from_be_bytes([msg[pos], msg[pos + 1]]);
        if qtype != RR_HTTPS {
            return None;
        }
        pos += 4;
    }

    for _ in 0..an {
        pos = skip_name(msg, pos)?;
        if pos + 10 > msg.len() {
            return None;
        }
        let rtype = u16::from_be_bytes([msg[pos], msg[pos + 1]]);
        let rdlen = u16::from_be_bytes([msg[pos + 8], msg[pos + 9]]) as usize;
        pos += 10;
        if pos + rdlen > msg.len() {
            return None;
        }
        if rtype == RR_HTTPS {
            if let Some(ech) = parse_svcparams_ech(msg, pos, rdlen) {
                return Some(ech);
            }
        }
        pos += rdlen;
    }
    None
}

fn parse_svcparams_ech(msg: &[u8], rdata_start: usize, rdlen: usize) -> Option<Vec<u8>> {
    let end = rdata_start + rdlen;
    if rdata_start + 2 > end {
        return None;
    }
    let mut p = skip_name(msg, rdata_start + 2)?;

    while p + 4 <= end {
        let key = u16::from_be_bytes([msg[p], msg[p + 1]]);
        let len = u16::from_be_bytes([msg[p + 2], msg[p + 3]]) as usize;
        p += 4;
        if p + len > end {
            return None;
        }
        if key == SVCPARAM_ECH {
            return Some(msg[p..p + len].to_vec());
        }
        p += len;
    }
    None
}

/// Decode an uncompressed wire name. Question-section names are never
/// compressed, so a pointer here is a forged or malformed reply.
fn read_name(buf: &[u8], mut pos: usize) -> Option<String> {
    let mut labels: Vec<String> = Vec::new();
    loop {
        let len = *buf.get(pos)?;
        if len & 0xc0 == 0xc0 {
            return None;
        }
        if len == 0 {
            break;
        }
        let start = pos + 1;
        let end = start.checked_add(len as usize)?;
        if end > buf.len() {
            return None;
        }
        labels.push(String::from_utf8_lossy(&buf[start..end]).to_string());
        pos = end;
    }
    Some(labels.join("."))
}

fn skip_name(buf: &[u8], mut pos: usize) -> Option<usize> {
    loop {
        let len = *buf.get(pos)?;
        if len & 0xc0 == 0xc0 {
            return Some(pos + 2);
        }
        if len == 0 {
            return Some(pos + 1);
        }
        pos += 1 + len as usize;
    }
}

// ─── Shared data-plane probe builder ───────────────────────────────────────

/// Compute the IPv4 header checksum over a 20-byte header (checksum field at
/// offset 10..12 is treated as zero during computation).
pub fn ipv4_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < header.len() {
        if i == 10 {
            i += 2;
            continue;
        }
        sum += u16::from_be_bytes([header[i], header[i + 1]]) as u32;
        i += 2;
    }
    if i < header.len() {
        sum += (header[i] as u32) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Build a raw IPv4 + UDP + DNS A-query packet for in-tunnel data-plane
/// validation. The packet is sent *inside* the encrypted tunnel to prove the
/// L3 path works — it never leaks outside.
///
/// `src` is the tunnel-local IPv4 address; `resolver` is the upstream DNS
/// target (typically 1.1.1.1 or 8.8.8.8).
/// The IPv4 resolver the data-plane probe targets. Configurable via
/// `AETHER_DATAPLANE_PROBE_IP` because the default (8.8.8.8) is blocked in some
/// regions, which would make a perfectly good tunnel fail verification.
pub fn dataplane_probe_target() -> Ipv4Addr {
    crate::runtime_env::var("AETHER_DATAPLANE_PROBE_IP")
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(Ipv4Addr::new(8, 8, 8, 8))
}

pub fn build_dataplane_probe(src: Ipv4Addr, resolver: Ipv4Addr) -> Vec<u8> {
    // DNS A query for cloudflare.com
    let mut dns = Vec::with_capacity(64);
    let id: u16 = rand::random();
    dns.extend_from_slice(&id.to_be_bytes());
    dns.extend_from_slice(&[0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    for label in ["cloudflare", "com"] {
        dns.push(label.len() as u8);
        dns.extend_from_slice(label.as_bytes());
    }
    dns.push(0);
    dns.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // A IN

    let udp_len = 8 + dns.len();
    let total = 20 + udp_len;
    let mut pkt = Vec::with_capacity(total);
    // IPv4 header
    pkt.push(0x45);
    pkt.push(0x00);
    pkt.extend_from_slice(&(total as u16).to_be_bytes());
    pkt.extend_from_slice(&rand::random::<u16>().to_be_bytes()); // identification
    pkt.extend_from_slice(&[0x00, 0x00]); // flags + fragment
    pkt.push(64); // TTL
    pkt.push(17); // protocol: UDP
    pkt.extend_from_slice(&[0x00, 0x00]); // checksum placeholder
    pkt.extend_from_slice(&src.octets());
    pkt.extend_from_slice(&resolver.octets());
    let csum = ipv4_checksum(&pkt[0..20]);
    pkt[10..12].copy_from_slice(&csum.to_be_bytes());
    // UDP header
    let sport: u16 = 40000 + (rand::random::<u16>() % 20000);
    pkt.extend_from_slice(&sport.to_be_bytes());
    pkt.extend_from_slice(&53u16.to_be_bytes());
    pkt.extend_from_slice(&(udp_len as u16).to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x00]); // UDP checksum (optional for IPv4)
    // DNS payload
    pkt.extend_from_slice(&dns);
    pkt
}

/// Validate that an inbound IPv4 datagram is a UDP DNS reply from the given
/// resolver on port 53. Currently exercised only by tests (the live data-plane
/// path decodes QUIC DATAGRAMs), so it is compiled for tests only.
#[cfg(test)]
pub fn is_dns_reply(pkt: &[u8], resolver: Ipv4Addr) -> bool {
    if pkt.len() < 28 || pkt[0] >> 4 != 4 {
        return false;
    }
    let ihl = ((pkt[0] & 0x0f) as usize) * 4;
    if ihl < 20 || pkt.len() < ihl + 8 || pkt[9] != 17 {
        return false;
    }
    if pkt[12..16] != resolver.octets() {
        return false;
    }
    u16::from_be_bytes([pkt[ihl], pkt[ihl + 1]]) == 53
}

#[cfg(test)]
mod tests {
    use super::{parse_https_ech, read_name, RR_HTTPS};

    const QID: u16 = 0x1234;
    const NAME: &str = "cloudflare-ech.com";

    /// `flags`, `ancount` and the echoed name are the parts an attacker varies.
    fn reply(flags: u16, an: u16, name: &str) -> Vec<u8> {
        let mut msg = Vec::new();
        msg.extend_from_slice(&QID.to_be_bytes());
        msg.extend_from_slice(&flags.to_be_bytes());
        msg.extend_from_slice(&[0, 1, an.to_be_bytes()[0], an.to_be_bytes()[1], 0, 0, 0, 0]);
        for label in name.split('.') {
            msg.push(label.len() as u8);
            msg.extend_from_slice(label.as_bytes());
        }
        msg.push(0);
        msg.extend_from_slice(&RR_HTTPS.to_be_bytes());
        msg.extend_from_slice(&[0x00, 0x01]);
        if an == 0 {
            return msg;
        }
        // Answer: pointer to the question name, HTTPS rdata with an `ech` param.
        msg.extend_from_slice(&[0xc0, 0x0c]);
        let rdata: Vec<u8> = vec![
            0x00, 0x00, // SVC priority
            0x00, // empty target name
            0x00, 0x05, // SvcParamKey = ech
            0x00, 0x04, // SvcParamValue length
            0xde, 0xad, 0xbe, 0xef,
        ];
        msg.extend_from_slice(&RR_HTTPS.to_be_bytes());
        msg.extend_from_slice(&[0x00, 0x01]);
        msg.extend_from_slice(&[0, 0, 0, 60]);
        msg.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        msg.extend_from_slice(&rdata);
        msg
    }

    #[test]
    fn accepts_a_well_formed_answer() {
        let msg = reply(0x8180, 1, NAME);
        assert_eq!(parse_https_ech(&msg, QID, NAME).as_deref(), Some(&[0xde, 0xad, 0xbe, 0xef][..]));
    }

    #[test]
    fn rejects_forged_or_unasked_for_answers() {
        // Right shape, wrong transaction id: this is what an off-path spoof or a
        // late reply to an earlier query looks like.
        assert_eq!(parse_https_ech(&reply(0x8180, 1, NAME), 0x4321, NAME), None);
        // Answering a name nobody asked about must not configure ECH.
        assert_eq!(parse_https_ech(&reply(0x8180, 1, "evil.example"), QID, NAME), None);
        // Truncated: a partial ECHConfig is worse than none.
        assert_eq!(parse_https_ech(&reply(0x8380, 1, NAME), QID, NAME), None);
        // Not a response, an error, or a non-standard opcode.
        assert_eq!(parse_https_ech(&reply(0x0180, 1, NAME), QID, NAME), None);
        assert_eq!(parse_https_ech(&reply(0x8183, 1, NAME), QID, NAME), None);
        assert_eq!(parse_https_ech(&reply(0x8180, 0, NAME), QID, NAME), None);
        assert_eq!(parse_https_ech(&[0u8; 4], QID, NAME), None);
    }

    #[test]
    fn read_name_refers_to_compression() {
        let mut buf = Vec::new();
        buf.push(3);
        buf.extend_from_slice(b"www");
        buf.push(7);
        buf.extend_from_slice(b"example");
        buf.extend_from_slice(b"");
        buf.push(3);
        buf.extend_from_slice(b"com");
        buf.push(0);
        assert_eq!(read_name(&buf, 0).as_deref(), Some("www.example.com"));
        // A pointer in the question section is not legal.
        let ptr = [0xc0, 0x0c];
        assert_eq!(read_name(&ptr, 0), None);
    }
}
