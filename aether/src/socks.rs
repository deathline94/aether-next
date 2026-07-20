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

pub async fn serve(listen: SocketAddr, stack: StackHandle) -> Result<()> {
    serve_listener(bind(listen).await?, stack).await
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

pub async fn dns_resolve(stack: &StackHandle, name: &str) -> Result<IpAddr> {
    let key = name.to_ascii_lowercase();
    if let Ok(guard) = dns_cache().lock() {
        if let Some((ip, at)) = guard.map.get(&key) {
            if at.elapsed() < DNS_CACHE_TTL {
                return Ok(*ip);
            }
        }
    }

    let udp = stack.open_udp().await?;
    let server: SocketAddr = "1.1.1.1:53".parse().unwrap();
    let (sender, mut from_stack) = udp.into_split();

    let mut last_err = AetherError::Other(format!("no DNS record for {name}"));
    for qtype in dns_prefer_order() {
        let (qid, query) = build_dns_query(name, qtype);
        if let Err(e) = sender.send_to(server, query).await {
            last_err = e;
            continue;
        }
        let resp = match tokio::time::timeout(Duration::from_secs(3), from_stack.recv()).await {
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
        if let Some(ip) = parse_dns_answer_id(&resp.1, qtype, Some(qid)) {
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

fn parse_dns_answer(resp: &[u8], want_type: u16) -> Option<IpAddr> {
    parse_dns_answer_id(resp, want_type, None)
}

fn parse_dns_answer_id(resp: &[u8], want_type: u16, expect_id: Option<u16>) -> Option<IpAddr> {
    if resp.len() < 12 {
        return None;
    }
    if let Some(id) = expect_id {
        let got = u16::from_be_bytes([resp[0], resp[1]]);
        if got != id {
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
    let conn = match stack.open_tcp(dst).await {
        Ok(c) => c,
        Err(e) => {
            let _ = reply(&mut sock, REP_GENERAL).await;
            return Err(e);
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
                if let Some((dst, payload)) = parse_udp_request(&cbuf[..n]) {
                    let dst = match dst {
                        Target::Ip(ip) => SocketAddr::new(ip, payload.0),
                        Target::Domain(name) => {
                            match dns_resolve(&stack, &name).await {
                                Ok(ip) => SocketAddr::new(ip, payload.0),
                                Err(_) => continue,
                            }
                        }
                    };
                    let _ = sender.send_to(dst, payload.1).await;
                }
            }

            maybe = from_stack.recv() => {
                let (src, data) = match maybe { Some(v) => v, None => break };
                if let Some(c) = client {
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
    use super::{parse_dns_answer, select_auth_method};

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
        let ip = parse_dns_answer(&resp, 1).expect("A");
        assert_eq!(ip.to_string(), "1.2.3.4");

        let mut resp6 = vec![0, 1, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
        resp6.extend_from_slice(&[1, b'a', 3, b'c', b'o', b'm', 0, 0, 28, 0, 1]);
        let mut ans = vec![0xc0, 0x0c, 0, 28, 0, 1, 0, 0, 0, 60, 0, 16];
        ans.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        resp6.extend_from_slice(&ans);
        let ip6 = parse_dns_answer(&resp6, 28).expect("AAAA");
        assert_eq!(ip6.to_string(), "2001:db8::1");
    }
}
