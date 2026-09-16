use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

use crate::error::{AetherError, Result};
use crate::netstack::StackHandle;

const DNS_CACHE_TTL: Duration = Duration::from_secs(300);
const RELAY_BUF: usize = 256 * 1024;
const MAX_CLIENTS: usize = 256;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_SESSION: Duration = Duration::from_secs(4 * 60 * 60);

struct DnsCache {
    map: HashMap<String, (IpAddr, Instant)>,
}

fn dns_cache() -> &'static Mutex<DnsCache> {
    static CACHE: OnceLock<Mutex<DnsCache>> = OnceLock::new();
    CACHE.get_or_init(|| {
        Mutex::new(DnsCache {
            map: HashMap::new(),
        })
    })
}

const VER: u8 = 0x05;
const CMD_CONNECT: u8 = 0x01;
const CMD_UDP_ASSOCIATE: u8 = 0x03;
const ATYP_V4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_V6: u8 = 0x04;
const REP_OK: u8 = 0x00;
const REP_GENERAL: u8 = 0x01;
const REP_NOT_SUPPORTED: u8 = 0x07;

enum Target {
    Ip(IpAddr),
    Domain(String),
}

pub async fn bind(listen: SocketAddr) -> Result<TcpListener> {
    if !listen.ip().is_loopback() && std::env::var_os("AETHER_UNSAFE_PUBLIC_PROXY").is_none() {
        return Err(AetherError::Other("refusing non-loopback SOCKS bind".into()));
    }
    Ok(TcpListener::bind(listen).await?)
}

pub async fn serve_listener(listener: TcpListener, stack: StackHandle) -> Result<()> {
    let listen = listener.local_addr()?;
    log::info!("socks5 listening on {listen}");

    let permits = Arc::new(tokio::sync::Semaphore::new(MAX_CLIENTS));
    loop {
        let (sock, peer) = listener.accept().await?;
        let permit = match permits.clone().try_acquire_owned() { Ok(p) => p, Err(_) => continue };
        let _ = sock.set_nodelay(true);
        let stack = stack.clone();
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(e) = tokio::time::timeout(MAX_SESSION, handle_client(sock, stack)).await
                .map_err(|_| AetherError::Other("SOCKS maximum session duration reached".into()))
                .and_then(|r| r) {
                log::debug!("socks client {peer} ended: {e}");
            }
        });
    }
}

async fn handle_client(mut sock: TcpStream, stack: StackHandle) -> Result<()> {
    let (cmd, target, port) = tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
        handshake(&mut sock).await?;
        let mut head = [0u8; 4];
        sock.read_exact(&mut head).await?;
        if head[0] != VER { return Err(AetherError::Other("bad socks version".into())); }
        let (target, port) = read_target(&mut sock, head[3]).await?;
        Ok::<_, AetherError>((head[1], target, port))
    }).await.map_err(|_| AetherError::Other("SOCKS handshake timeout".into()))??;

    match cmd {
        CMD_CONNECT => handle_connect(sock, stack, target, port).await,
        CMD_UDP_ASSOCIATE => handle_udp_associate(sock, stack).await,
        _ => {
            reply(&mut sock, REP_NOT_SUPPORTED).await?;
            Err(AetherError::Other("unsupported socks command".into()))
        }
    }
}

async fn handshake(sock: &mut TcpStream) -> Result<()> {
    let mut prefix = [0u8; 2];
    sock.read_exact(&mut prefix).await?;
    if prefix[0] != VER {
        return Err(AetherError::Other("bad greeting version".into()));
    }
    let nmethods = prefix[1] as usize;
    let mut methods = vec![0u8; nmethods];
    sock.read_exact(&mut methods).await?;
    let method = select_auth_method(&methods);
    sock.write_all(&[VER, method]).await?;
    if method == 0xff {
        return Err(AetherError::Other(
            "no supported socks authentication method".into(),
        ));
    }
    Ok(())
}

fn select_auth_method(methods: &[u8]) -> u8 {
    if methods.contains(&0x00) {
        0x00
    } else {
        0xff
    }
}

async fn read_target(sock: &mut TcpStream, atyp: u8) -> Result<(Target, u16)> {
    let target = match atyp {
        ATYP_V4 => {
            let mut b = [0u8; 4];
            sock.read_exact(&mut b).await?;
            Target::Ip(IpAddr::V4(Ipv4Addr::from(b)))
        }
        ATYP_V6 => {
            let mut b = [0u8; 16];
            sock.read_exact(&mut b).await?;
            Target::Ip(IpAddr::V6(b.into()))
        }
        ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            sock.read_exact(&mut len).await?;
            let mut name = vec![0u8; len[0] as usize];
            sock.read_exact(&mut name).await?;
            Target::Domain(String::from_utf8_lossy(&name).to_string())
        }
        _ => return Err(AetherError::Other("bad atyp".into())),
    };

    let mut port = [0u8; 2];
    sock.read_exact(&mut port).await?;
    Ok((target, u16::from_be_bytes(port)))
}

async fn reply(sock: &mut TcpStream, code: u8) -> Result<()> {
    sock.write_all(&[VER, code, 0x00, ATYP_V4, 0, 0, 0, 0, 0, 0])
        .await?;
    Ok(())
}

async fn reply_bound(sock: &mut TcpStream, bound: SocketAddr) -> Result<()> {
    let mut buf = vec![VER, REP_OK, 0x00];
    match bound.ip() {
        IpAddr::V4(v4) => {
            buf.push(ATYP_V4);
            buf.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            buf.push(ATYP_V6);
            buf.extend_from_slice(&v6.octets());
        }
    }
    buf.extend_from_slice(&bound.port().to_be_bytes());
    sock.write_all(&buf).await?;
    Ok(())
}

async fn resolve(stack: &StackHandle, target: Target) -> Result<IpAddr> {
    match target {
        Target::Ip(ip) => Ok(ip),
        Target::Domain(name) => {
            if let Ok(ip) = name.parse::<IpAddr>() {
                return Ok(ip);
            }
            dns_resolve(stack, &name).await
        }
    }
}

fn dns_prefer_order() -> Vec<u16> {
    // 1=A, 28=AAAA. Respect AETHER_IP when set.
    match crate::runtime_env::var("AETHER_IP")
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "4" | "v4" | "ipv4" => vec![1],
        "6" | "v6" | "ipv6" => vec![28, 1],
        _ => vec![1, 28],
    }
}

pub fn parse_dns_server_entry(entry: &str) -> Option<SocketAddr> {
    let p = entry.trim();
    if p.is_empty() {
        return None;
    }
    // 1. Bare IP (IPv4 or bare unbracketed IPv6 like "2606:4700:4700::1111")
    if let Ok(ip) = p.parse::<IpAddr>() {
        return Some(SocketAddr::new(ip, 53));
    }
    // 2. Bracketed IPv6 without port: "[2606:4700:4700::1111]"
    if p.starts_with('[') && p.ends_with(']') {
        if let Ok(ip) = p[1..p.len() - 1].parse::<IpAddr>() {
            return Some(SocketAddr::new(ip, 53));
        }
    }
    // 3. SocketAddr with explicit port: "1.1.1.1:5353" or "[2606:4700:4700::1111]:5353"
    p.parse::<SocketAddr>().ok()
}

pub fn parse_dns_servers(raw: &str) -> Vec<SocketAddr> {
    let mut out = Vec::new();
    for part in raw.split(',') {
        let p = part.trim();
        if p.is_empty() {
            continue;
        }
        if let Some(a) = parse_dns_server_entry(p) {
            out.push(a);
        } else {
            log::warn!("[socks-dns] ignoring unparseable AETHER_DNS entry {p:?}");
        }
    }
    if out.is_empty() {
        out.push("1.1.1.1:53".parse().unwrap());
        out.push("1.0.0.1:53".parse().unwrap());
    }
    out
}

/// Resolvers are configurable (`AETHER_DNS=ip[,ip...]`, bare IP or
/// `ip:port`; bare IPv6 literals are accepted and paired with port 53).
fn configured_dns_servers() -> Vec<SocketAddr> {
    let raw = crate::runtime_env::var("AETHER_DNS").unwrap_or_default();
    parse_dns_servers(&raw)
}

fn valid_dns_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 253
        && name.split('.').all(|l| !l.is_empty() && l.len() <= 63)
}

pub async fn dns_resolve(stack: &StackHandle, name: &str) -> Result<IpAddr> {
    let key = name.to_ascii_lowercase();
    if let Ok(guard) = dns_cache().lock() {
        if let Some((ip, at)) = guard.map.get(&key) {
            if at.elapsed() < DNS_CACHE_TTL {
                return Ok(*ip);
            }
        }
    }
    if !valid_dns_name(&key) {
        return Err(AetherError::Other(format!("invalid domain name {name:?}")));
    }

    // The UdpSender's Drop now closes the netstack socket (H1 fix), so every
    // return path below frees the socket + buffers instead of leaking them
    // until MAX_UDP_CONNECTIONS permanently broke resolution.
    let udp = stack.open_udp().await?;
    let (sender, mut from_stack) = udp.into_split();

    let mut last_err = AetherError::Other(format!("no DNS record for {name}"));
    for server in configured_dns_servers() {
        for qtype in dns_prefer_order() {
            let (qid, query) = build_dns_query(name, qtype);
            if let Err(e) = sender.send_to(server, query).await {
                last_err = e;
                break; // server unreachable; try the next one
            }
            let (src, resp) =
                match tokio::time::timeout(Duration::from_secs(3), from_stack.recv()).await {
                    Ok(Some(r)) => r,
                    Ok(None) => {
                        last_err = AetherError::Other("dns channel closed".into());
                        continue;
                    }
                    Err(_) => {
                        last_err = AetherError::Other("dns timeout".into());
                        continue;
                    }
                };
            // M11 fix: only accept replies from the resolver we actually asked.
            if src != server {
                log::debug!("[socks-dns] dropping reply from {src} (asked {server})");
                last_err = AetherError::Other("dns reply from unexpected source".into());
                continue;
            }
            if let Some(ip) = parse_dns_answer_id(&resp, qtype, Some(qid), Some(&key)) {
                if let Ok(mut guard) = dns_cache().lock() {
                    guard.map.insert(key, (ip, Instant::now()));
                    if guard.map.len() > 2048 {
                        guard.map.retain(|_, (_, at)| at.elapsed() < DNS_CACHE_TTL);
                    }
                }
                return Ok(ip);
            }
            last_err = AetherError::Other(format!("no type-{qtype} record for {name}"));
        }
    }
    Err(last_err)
}

pub async fn resolve_host(stack: &StackHandle, name: &str) -> Result<IpAddr> {
    match name.parse::<IpAddr>() {
        Ok(ip) => Ok(ip),
        Err(_) => dns_resolve(stack, name).await,
    }
}

fn build_dns_query(name: &str, qtype: u16) -> (u16, Vec<u8>) {
    let mut q = Vec::with_capacity(32 + name.len());
    let id: u16 = rand::random();
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&[0x01, 0x00]);
    q.extend_from_slice(&[0x00, 0x01]);
    q.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    for label in name.split('.') {
        if label.is_empty() || label.len() > 63 {
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

fn parse_dns_answer_id(
    resp: &[u8],
    want_type: u16,
    expect_id: Option<u16>,
    expect_name: Option<&str>,
) -> Option<IpAddr> {
    if resp.len() < 12 {
        return None;
    }
    if let Some(id) = expect_id {
        let got = u16::from_be_bytes([resp[0], resp[1]]);
        if got != id {
            return None;
        }
    }
    // M11 fix: the response's question name must echo what we asked. Without
    // this, a same-socket stray/mismatched reply (only qid was checked before)
    // could be parsed as an answer for a different domain.
    if let Some(want) = expect_name {
        let got = decode_qname(resp, 12)?;
        if got.as_str() != want.trim_end_matches('.') {
            return None;
        }
    }
    // Truncated (TC bit) — refuse; caller may retry or fail.
    if resp[2] & 0x02 != 0 {
        return None;
    }
    let qd = u16::from_be_bytes([resp[4], resp[5]]) as usize;
    let an = u16::from_be_bytes([resp[6], resp[7]]) as usize;
    let mut pos = 12;

    for _ in 0..qd {
        pos = skip_name(resp, pos)?;
        pos = pos.checked_add(4)?;
    }

    for _ in 0..an {
        pos = skip_name(resp, pos)?;
        if pos + 10 > resp.len() {
            return None;
        }
        let rtype = u16::from_be_bytes([resp[pos], resp[pos + 1]]);
        let rdlen = u16::from_be_bytes([resp[pos + 8], resp[pos + 9]]) as usize;
        pos += 10;
        if pos + rdlen > resp.len() {
            return None;
        }
        if rtype == want_type && want_type == 1 && rdlen == 4 {
            return Some(IpAddr::V4(Ipv4Addr::new(
                resp[pos],
                resp[pos + 1],
                resp[pos + 2],
                resp[pos + 3],
            )));
        }
        if rtype == want_type && want_type == 28 && rdlen == 16 {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&resp[pos..pos + 16]);
            return Some(IpAddr::V6(std::net::Ipv6Addr::from(octets)));
        }
        pos += rdlen;
    }
    None
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

/// Decode a DNS name starting at `pos`, following compression pointers (bounded).
/// Returns the lowercase dotted name without a trailing dot.
fn decode_qname(buf: &[u8], mut pos: usize) -> Option<String> {
    let mut labels: Vec<String> = Vec::new();
    let mut jumps = 0usize;
    loop {
        let len = *buf.get(pos)?;
        if len & 0xc0 == 0xc0 {
            let lo = *buf.get(pos + 1)?;
            let ptr = (((len & 0x3f) as usize) << 8) | lo as usize;
            jumps += 1;
            if jumps > 4 || ptr >= buf.len() {
                return None;
            }
            pos = ptr;
            continue;
        }
        if len == 0 {
            if labels.is_empty() || labels.len() > 16 {
                return None;
            }
            let mut s = labels.join(".");
            s.make_ascii_lowercase();
            return Some(s);
        }
        let end = pos + 1 + len as usize;
        let slc = buf.get(pos + 1..end)?;
        if !slc
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
        {
            return None;
        }
        labels.push(String::from_utf8_lossy(slc).to_string());
        pos = end;
    }
}

async fn handle_connect(
    mut sock: TcpStream,
    stack: StackHandle,
    target: Target,
    port: u16,
) -> Result<()> {
    let ip = match resolve(&stack, target).await {
        Ok(ip) => ip,
        Err(e) => {
            let _ = reply(&mut sock, REP_GENERAL).await;
            return Err(e);
        }
    };

    let dst = SocketAddr::new(ip, port);
    // Belt-and-braces around the smoltcp socket connect-timeout (netstack): a
    // caller-side bound guarantees the client gets a SOCKS error reply instead
    // of hanging even if some other stall keeps the socket from resolving.
    let conn = match tokio::time::timeout(Duration::from_secs(20), stack.open_tcp(dst)).await {
        Ok(Ok(c)) => c,
        Ok(Err(e)) => {
            let _ = reply(&mut sock, REP_GENERAL).await;
            return Err(e);
        }
        Err(_) => {
            let _ = reply(&mut sock, REP_GENERAL).await;
            return Err(AetherError::Other("upstream connect timed out".into()));
        }
    };

    reply_bound(&mut sock, "0.0.0.0:0".parse().unwrap()).await?;

    let (sender, mut from_stack) = conn.into_split();
    let (mut rd, mut wr) = sock.into_split();

    let up = tokio::spawn(async move {
        let mut buf = vec![0u8; RELAY_BUF];
        loop {
            match rd.read(&mut buf).await {
                Ok(0) => {
                    sender.close().await;
                    break;
                }
                Ok(n) => {
                    if sender.send(buf[..n].to_vec()).await.is_err() {
                        break;
                    }
                }
                Err(_) => {
                    sender.close().await;
                    break;
                }
            }
        }
    });

    while let Some(first) = from_stack.recv().await {
        // Coalesce queued chunks into fewer write syscalls on bulk download.
        let mut batch = first;
        while batch.len() < RELAY_BUF {
            match from_stack.try_recv() {
                Ok(more) => {
                    if batch.len() + more.len() > RELAY_BUF * 2 {
                        // Flush current then keep the overflow as next batch base.
                        if wr.write_all(&batch).await.is_err() {
                            let _ = wr.shutdown().await;
                            up.abort();
                            return Ok(());
                        }
                        batch = more;
                    } else {
                        batch.extend_from_slice(&more);
                    }
                }
                Err(_) => break,
            }
        }
        if wr.write_all(&batch).await.is_err() {
            break;
        }
    }

    let _ = wr.shutdown().await;
    up.abort();
    Ok(())
}

async fn handle_udp_associate(mut sock: TcpStream, stack: StackHandle) -> Result<()> {
    let relay = UdpSocket::bind("127.0.0.1:0").await?;
    let relay_addr = relay.local_addr()?;
    reply_bound(&mut sock, relay_addr).await?;

    let udp = stack.open_udp().await?;
    let (sender, mut from_stack) = udp.into_split();

    // M6 fix: domain destinations used to be resolved inline in the select loop,
    // stalling ALL relay traffic for up to ~6s per lookup. Hostname sends are now
    // handed to a dedicated resolver task so the data path never blocks on DNS.
    let (res_tx, mut res_rx) = tokio::sync::mpsc::channel::<(String, u16, Vec<u8>, SocketAddr)>(64);
    let resolver_sender = sender.clone();
    let routes: Arc<Mutex<HashMap<SocketAddr, SocketAddr>>> = Arc::new(Mutex::new(HashMap::new()));
    let resolver_routes = routes.clone();
    tokio::spawn(async move {
        while let Some((name, port, payload, from)) = res_rx.recv().await {
            match tokio::time::timeout(Duration::from_secs(4), dns_resolve(&stack, &name)).await {
                Ok(Ok(ip)) => {
                    let dst = SocketAddr::new(ip, port);
                    if let Ok(mut map) = resolver_routes.lock() {
                        map.insert(dst, from);
                        if map.len() > 2048 {
                            map.clear();
                        }
                    }
                    let _ = resolver_sender
                        .send_to(dst, payload)
                        .await;
                }
                _ => log::debug!("[socks-udp] resolve failed for {name}; dropping datagram"),
            }
        }
    });

    // First UDP packet pins the authorized client; later packets from others are dropped.
    let mut client: Option<SocketAddr> = None;
    let mut cbuf = vec![0u8; 65535];
    let mut ctrl = [0u8; 256];

    loop {
        tokio::select! {
            r = relay.recv_from(&mut cbuf) => {
                let (n, from) = match r { Ok(v) => v, Err(_) => break };
                match client {
                    None => client = Some(from),
                    Some(allowed) if allowed == from => {}
                    Some(allowed)
                        if allowed.ip() == from.ip() && from.ip().is_loopback() =>
                    {
                        // Same loopback host, new ephemeral port (common for
                        // multi-socket clients). Restricted to loopback so a
                        // non-loopback source can never rebind the session (L2 fix).
                        log::debug!("socks udp client rebind {allowed} -> {from}");
                        client = Some(from);
                    }
                    Some(_) => continue, // reject any other source
                }
                let Some((dst, payload)) = parse_udp_request(&cbuf[..n]) else { continue };
                match dst {
                    Target::Ip(ip) => {
                        let dst = SocketAddr::new(ip, payload.0);
                        if let Ok(mut map) = routes.lock() {
                            map.insert(dst, from);
                            if map.len() > 2048 {
                                map.clear();
                            }
                        }
                        let _ = sender.send_to(dst, payload.1).await;
                    }
                    Target::Domain(name) => {
                        if res_tx.try_send((name, payload.0, payload.1, from)).is_err() {
                            log::debug!("socks udp resolver backlog full; dropping datagram");
                        }
                    }
                }
            }

            maybe = from_stack.recv() => {
                let (src, data) = match maybe { Some(v) => v, None => break };
                let target_client = {
                    routes.lock().ok().and_then(|map| map.get(&src).copied()).or(client)
                };
                if let Some(c) = target_client {
                    let pkt = build_udp_reply(src, &data);
                    let _ = relay.send_to(&pkt, c).await;
                }
            }

            r = sock.read(&mut ctrl) => {
                match r { Ok(0) | Err(_) => break, Ok(_) => {} }
            }
        }
    }

    sender.close().await;
    Ok(())
}

fn parse_udp_request(buf: &[u8]) -> Option<(Target, (u16, Vec<u8>))> {
    if buf.len() < 4 || buf[2] != 0 {
        return None;
    }
    let atyp = buf[3];
    let mut pos = 4;
    let target = match atyp {
        ATYP_V4 => {
            if buf.len() < pos + 4 {
                return None;
            }
            let ip = Ipv4Addr::new(buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3]);
            pos += 4;
            Target::Ip(IpAddr::V4(ip))
        }
        ATYP_V6 => {
            if buf.len() < pos + 16 {
                return None;
            }
            let mut b = [0u8; 16];
            b.copy_from_slice(&buf[pos..pos + 16]);
            pos += 16;
            Target::Ip(IpAddr::V6(b.into()))
        }
        ATYP_DOMAIN => {
            let len = *buf.get(pos)? as usize;
            pos += 1;
            if buf.len() < pos + len {
                return None;
            }
            let name = String::from_utf8_lossy(&buf[pos..pos + len]).to_string();
            pos += len;
            Target::Domain(name)
        }
        _ => return None,
    };

    if buf.len() < pos + 2 {
        return None;
    }
    let port = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
    pos += 2;
    Some((target, (port, buf[pos..].to_vec())))
}

fn build_udp_reply(src: SocketAddr, data: &[u8]) -> Vec<u8> {
    let mut pkt = vec![0x00, 0x00, 0x00];
    match src.ip() {
        IpAddr::V4(v4) => {
            pkt.push(ATYP_V4);
            pkt.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            pkt.push(ATYP_V6);
            pkt.extend_from_slice(&v6.octets());
        }
    }
    pkt.extend_from_slice(&src.port().to_be_bytes());
    pkt.extend_from_slice(data);
    pkt
}

#[cfg(test)]
mod tests {
    use super::{decode_qname, parse_dns_answer_id, select_auth_method};

    #[test]
    fn parses_dns_servers_handles_bare_and_bracketed_ipv6_and_ports() {
        use super::{parse_dns_server_entry, parse_dns_servers};

        assert_eq!(
            parse_dns_server_entry("1.1.1.1"),
            Some("1.1.1.1:53".parse().unwrap())
        );
        assert_eq!(
            parse_dns_server_entry("8.8.8.8:5353"),
            Some("8.8.8.8:5353".parse().unwrap())
        );
        assert_eq!(
            parse_dns_server_entry("2606:4700:4700::1111"),
            Some("[2606:4700:4700::1111]:53".parse().unwrap())
        );
        assert_eq!(
            parse_dns_server_entry("[2606:4700:4700::1111]"),
            Some("[2606:4700:4700::1111]:53".parse().unwrap())
        );
        assert_eq!(
            parse_dns_server_entry("[2606:4700:4700::1111]:5353"),
            Some("[2606:4700:4700::1111]:5353".parse().unwrap())
        );
        assert_eq!(parse_dns_server_entry("   "), None);
        assert_eq!(parse_dns_server_entry("invalid:domain.com"), None);

        let servers = parse_dns_servers("2606:4700:4700::1111, 8.8.8.8:5353, [::1]");
        assert_eq!(servers.len(), 3);
        assert_eq!(servers[0], "[2606:4700:4700::1111]:53".parse().unwrap());
        assert_eq!(servers[1], "8.8.8.8:5353".parse().unwrap());
        assert_eq!(servers[2], "[::1]:53".parse().unwrap());

        // Fallback default
        let default_servers = parse_dns_servers("");
        assert_eq!(default_servers.len(), 2);
        assert_eq!(default_servers[0], "1.1.1.1:53".parse().unwrap());
        assert_eq!(default_servers[1], "1.0.0.1:53".parse().unwrap());
    }

    #[test]
    fn rejects_clients_without_no_auth_method() {
        assert_eq!(select_auth_method(&[0x02]), 0xff);
        assert_eq!(select_auth_method(&[0x02, 0x00]), 0x00);
    }

    #[test]
    fn parses_a_and_aaaa_answers() {
        // Minimal synthetic DNS response with one A answer (not full wire-valid; parser only walks answers).
        // Header: id=1, flags=0x8180, qd=1, an=1
        let mut resp = vec![0, 1, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
        // Question: a.com
        resp.extend_from_slice(&[1, b'a', 3, b'c', b'o', b'm', 0, 0, 1, 0, 1]);
        // Answer: pointer to name + type A + class IN + ttl + rdlen 4 + 1.2.3.4
        resp.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 1, 2, 3, 4]);
        let ip = parse_dns_answer_id(&resp, 1, None, Some("a.com")).expect("A");
        assert_eq!(ip.to_string(), "1.2.3.4");

        let mut resp6 = vec![0, 1, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
        resp6.extend_from_slice(&[1, b'a', 3, b'c', b'o', b'm', 0, 0, 28, 0, 1]);
        let mut ans = vec![0xc0, 0x0c, 0, 28, 0, 1, 0, 0, 0, 60, 0, 16];
        ans.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        resp6.extend_from_slice(&ans);
        let ip6 = parse_dns_answer_id(&resp6, 28, None, Some("a.com")).expect("AAAA");
        assert_eq!(ip6.to_string(), "2001:db8::1");
    }

    #[test]
    fn rejects_reply_for_a_different_name() {
        // Same wire shape as the A-answer test, but we asked for other.com —
        // the question-name echo check must reject it.
        let mut resp = vec![0, 1, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
        resp.extend_from_slice(&[1, b'a', 3, b'c', b'o', b'm', 0, 0, 1, 0, 1]);
        resp.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 1, 2, 3, 4]);
        assert!(parse_dns_answer_id(&resp, 1, Some(1), Some("other.com")).is_none());
    }

    #[test]
    fn decodes_compressed_qname() {
        let mut buf = vec![0u8; 12];
        buf.extend_from_slice(&[3, b'w', b'w', b'w', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0]);
        // Pointer from elsewhere back to offset 12.
        let with_ptr = [0xc0, 0x0c];
        let mut full = buf.clone();
        full.extend_from_slice(&with_ptr);
        assert_eq!(decode_qname(&full, 12).as_deref(), Some("www.example.com"));
        assert_eq!(decode_qname(&full, full.len() - 2).as_deref(), Some("www.example.com"));
    }
}
