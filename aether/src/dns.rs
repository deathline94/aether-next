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
                    log::info!(
                        "fetched ECHConfigList ({} bytes) for {host} via {server}",
                        ech.len()
                    );
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
    let bind = if server.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let sock = UdpSocket::bind(bind).await?;
    sock.connect(server).await?;

    let (qid, query) = build_query(host, RR_HTTPS);
    sock.send(&query).await?;

    // A UDP datagram can carry up to 65535 bytes, and an HTTPS RR with an
    // ECHConfigList regularly exceeds 512 bytes. Read until a matching qid
    // arrives within the shared deadline, and fall back to TCP when TC=1.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    let mut buf = vec![0u8; 65535];
    loop {
        let n = tokio::time::timeout_at(deadline, sock.recv(&mut buf))
            .await
            .map_err(|_| AetherError::Ech("dns timeout".into()))??;
        let reply = &buf[..n];
        if reply.len() >= 12 && u16::from_be_bytes([reply[0], reply[1]]) == qid {
            if is_truncated_reply(reply, qid) {
                log::debug!(
                    "ech dns udp reply from {server} was truncated (TC=1); retrying over tcp"
                );
                let tcp_reply = query_tcp(server, &query).await?;
                return parse_https_ech(&tcp_reply, qid, host)
                    .ok_or_else(|| AetherError::Ech("no ech svcparam".into()));
            }
            return parse_https_ech(reply, qid, host)
                .ok_or_else(|| AetherError::Ech("no ech svcparam".into()));
        }
        log::debug!("discarding udp ech reply with mismatched transaction id");
    }
}

fn is_truncated_reply(msg: &[u8], qid: u16) -> bool {
    msg.len() >= 12
        && u16::from_be_bytes([msg[0], msg[1]]) == qid
        && (u16::from_be_bytes([msg[2], msg[3]]) & 0x8200) == 0x8200
}

async fn query_tcp(server: SocketAddr, query: &[u8]) -> Result<Vec<u8>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = timeout(
        Duration::from_secs(3),
        tokio::net::TcpStream::connect(server),
    )
    .await
    .map_err(|_| AetherError::Ech("dns tcp connect timeout".into()))??;
    let len_prefix =
        u16::try_from(query.len()).map_err(|_| AetherError::Ech("dns query too large".into()))?;
    timeout(Duration::from_secs(3), async {
        stream.write_all(&len_prefix.to_be_bytes()).await?;
        stream.write_all(query).await?;
        let mut hdr = [0u8; 2];
        stream.read_exact(&mut hdr).await?;
        let resp_len = u16::from_be_bytes(hdr) as usize;
        let mut resp = vec![0u8; resp_len];
        stream.read_exact(&mut resp).await?;
        Ok::<Vec<u8>, std::io::Error>(resp)
    })
    .await
    .map_err(|_| AetherError::Ech("dns tcp reply timeout".into()))?
    .map_err(Into::into)
}

fn build_query(name: &str, qtype: u16) -> (u16, Vec<u8>) {
    let mut q = Vec::with_capacity(44 + name.len());
    let id: u16 = rand::random();
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&[0x01, 0x00]); // RD=1
    q.extend_from_slice(&[0x00, 0x01]); // QDCOUNT=1
    q.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x01]); // ARCOUNT=1 (EDNS0 OPT)
    for label in name.split('.') {
        if label.is_empty() {
            continue;
        }
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0x00);
    q.extend_from_slice(&qtype.to_be_bytes());
    q.extend_from_slice(&[0x00, 0x01]); // IN
                                        // EDNS0 OPT RR (RFC 6891): root name, type=41, UDP payload=4096, ext-rcode/flags=0, rdlen=0
    q.extend_from_slice(&[
        0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ]);
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
    let end = rdata_start.checked_add(rdlen)?;
    if end > msg.len() || rdata_start + 2 > end {
        return None;
    }
    let rdata = &msg[..end];
    let mut p = skip_name_uncompressed(rdata, rdata_start + 2)?;

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

fn skip_name_uncompressed(buf: &[u8], mut pos: usize) -> Option<usize> {
    loop {
        let len = *buf.get(pos)?;
        if len & 0xc0 != 0 {
            return None;
        }
        if len == 0 {
            return Some(pos + 1);
        }
        pos = pos.checked_add(1 + len as usize)?;
        if pos > buf.len() {
            return None;
        }
    }
}

/// Decode an uncompressed wire name. Question-section names are never
/// compressed, so a pointer or reserved label bits (`0x40`/`0x80`) indicate a
/// malformed or forged reply.
fn read_name(buf: &[u8], mut pos: usize) -> Option<String> {
    let mut labels: Vec<String> = Vec::new();
    loop {
        let len = *buf.get(pos)?;
        if len & 0xc0 != 0 {
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

pub(crate) fn skip_name(buf: &[u8], mut pos: usize) -> Option<usize> {
    loop {
        let len = *buf.get(pos)?;
        let tag = len & 0xc0;
        if tag == 0xc0 {
            if pos + 2 > buf.len() {
                return None;
            }
            return Some(pos + 2);
        }
        if tag != 0 {
            return None;
        }
        if len == 0 {
            return Some(pos + 1);
        }
        pos = pos.checked_add(1 + len as usize)?;
        if pos > buf.len() {
            return None;
        }
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
/// The IPv4 resolver the data-plane probe targets. Defaults to Cloudflare DNS
/// (1.1.1.1) which lives directly inside the tunnel edge. Configurable via
/// `AETHER_DATAPLANE_PROBE_IP`.
pub fn dataplane_probe_target() -> Ipv4Addr {
    crate::runtime_env::var("AETHER_DATAPLANE_PROBE_IP")
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(Ipv4Addr::new(1, 1, 1, 1))
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

/// Validate that an inbound IPv4 datagram is a UDP DNS *reply* from the given
/// resolver on port 53.
///
/// This is the predicate the data-plane readiness gates use: "a datagram came
/// back" is not proof the tunnel forwards traffic, because the peer can echo our
/// own probe. Source address, source port and the QR bit are what separate a
/// reply from an echo or a spoofed fragment.
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
    if u16::from_be_bytes([pkt[ihl], pkt[ihl + 1]]) != 53 {
        return false;
    }
    // DNS header: flags at offset 2, QR is the top bit. An echo of the probe we
    // sent has QR clear, so it is not evidence of anything.
    if pkt.len() < ihl + 8 + 12 {
        return false;
    }
    pkt[ihl + 8 + 2] & 0x80 != 0
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
        assert_eq!(
            parse_https_ech(&msg, QID, NAME).as_deref(),
            Some(&[0xde, 0xad, 0xbe, 0xef][..])
        );
    }

    #[test]
    fn rejects_forged_or_unasked_for_answers() {
        // Right shape, wrong transaction id: this is what an off-path spoof or a
        // late reply to an earlier query looks like.
        assert_eq!(parse_https_ech(&reply(0x8180, 1, NAME), 0x4321, NAME), None);
        // Answering a name nobody asked about must not configure ECH.
        assert_eq!(
            parse_https_ech(&reply(0x8180, 1, "evil.example"), QID, NAME),
            None
        );
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

    #[tokio::test]
    async fn udp_query_skips_mismatched_qid_and_retries_tcp_when_truncated() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = udp.local_addr().unwrap();
        let tcp = tokio::net::TcpListener::bind(addr).await.unwrap();

        let server = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (n, peer) = udp.recv_from(&mut buf).await.unwrap();
            assert!(n >= 12);
            let qid = u16::from_be_bytes([buf[0], buf[1]]);

            // First packet has wrong transaction id; client must skip it.
            let mut wrong = reply(0x8180, 1, "cloudflare-ech.com");
            let wrong_qid = qid.wrapping_add(1);
            wrong[0..2].copy_from_slice(&wrong_qid.to_be_bytes());
            udp.send_to(&wrong, peer).await.unwrap();

            // Second UDP packet carries matching qid with TC=1 truncated bit set.
            let mut trunc = reply(0x8380, 1, "cloudflare-ech.com");
            trunc[0..2].copy_from_slice(&qid.to_be_bytes());
            udp.send_to(&trunc, peer).await.unwrap();

            // Expect client fallback over TCP.
            let (mut stream, _) = tcp.accept().await.unwrap();
            let mut len_hdr = [0u8; 2];
            stream.read_exact(&mut len_hdr).await.unwrap();
            let qlen = u16::from_be_bytes(len_hdr) as usize;
            let mut q = vec![0u8; qlen];
            stream.read_exact(&mut q).await.unwrap();
            let mut full = reply(0x8180, 1, "cloudflare-ech.com");
            full[0..2].copy_from_slice(&q[0..2]);
            stream
                .write_all(&(full.len() as u16).to_be_bytes())
                .await
                .unwrap();
            stream.write_all(&full).await.unwrap();
        });

        let ech = super::query_ech(addr, "cloudflare-ech.com").await.unwrap();
        assert_eq!(ech, vec![0xde, 0xad, 0xbe, 0xef]);
        server.await.unwrap();
    }
}
