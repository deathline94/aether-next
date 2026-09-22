use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use parking_lot::Mutex;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

use crate::error::{AetherError, Result};
use crate::netstack::StackHandle;

const DNS_CACHE_TTL: Duration = Duration::from_secs(300);
/// How long a destination may still receive relayed datagrams after the client
/// last sent to it. A QUIC connection migrates and idles; a NAT binding does
/// not survive much past a couple of minutes, so keeping origins forever only
/// widens the window in which an unsolicited source reaches the client.
const UDP_ORIGIN_TTL: Duration = Duration::from_secs(120);
const UDP_ORIGIN_MAX: usize = 2048;
const RELAY_BUF: usize = 256 * 1024;
const MAX_CLIENTS: usize = 256;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_SESSION: Duration = Duration::from_secs(4 * 60 * 60);

struct DnsCache {
    /// `(address, first-seen, last-used)`. `last-used` is what eviction ranks
    /// on: with only the insert time, `retain(ttl)` at the cap removed nothing
    /// while the TTL was long, so a wildcard-DNS page grew the map forever.
    map: HashMap<String, (IpAddr, Instant, Instant)>,
}

const DNS_CACHE_MAX: usize = 2048;

/// Drop the least-recently-used quarter of the cache once it is full.
/// Evicting a slice rather than one entry keeps the amortised cost of an
/// insert at O(1) instead of O(n) per insert at the cap.
fn evict_lru(cache: &mut DnsCache) {
    if cache.map.len() <= DNS_CACHE_MAX {
        return;
    }
    cache.map.retain(|_, (_, first, _)| first.elapsed() < DNS_CACHE_TTL);
    let target = DNS_CACHE_MAX - DNS_CACHE_MAX / 4;
    if cache.map.len() <= target {
        return;
    }
    let mut by_use: Vec<(Instant, String)> = cache
        .map
        .iter()
        .map(|(k, (_, _, used))| (*used, k.clone()))
        .collect();
    by_use.sort_unstable_by_key(|(used, _)| *used);
    for (_, key) in by_use.iter().take(by_use.len() - target) {
        cache.map.remove(key.as_str());
    }
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
/// RFC 1928 §6: 0x02 is "command not supported", 0x07 is "address type not
/// supported". Answering a refused *command* with 0x07 tells the client its
/// address was the problem, which sends it looking in the wrong place.
const REP_CMD_NOT_SUPPORTED: u8 = 0x02;
const REP_ATYP_NOT_SUPPORTED: u8 = 0x07;
const CMD_BIND: u8 = 0x02;

enum Target {
    Ip(IpAddr),
    Domain(String),
}

pub async fn bind(listen: SocketAddr) -> Result<TcpListener> {
    // Non-loopback binds are already rejected centrally in `engine_config`
    // (one knob, checked for both listeners before anything binds); a second
    // variable here was a second source of truth that could disagree with it.
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
        CMD_BIND => {
            // BIND is not implemented; refuse it with the command code and close
            // instead of falling through to a protocol-mislabelled reply.
            reply(&mut sock, REP_CMD_NOT_SUPPORTED).await?;
            Err(AetherError::Other("SOCKS BIND is not supported".into()))
        }
        _ => {
            reply(&mut sock, REP_CMD_NOT_SUPPORTED).await?;
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

/// Validate a wire-domain exactly as it will be put on the wire.
///
/// A lossy decode let a byte the client never sent become `U+FFFD`, and the
/// query builder then dropped labels it considered too long: the proxy looked
/// up a *different* host than the client asked for and reported success.
fn parse_domain_name(raw: &[u8]) -> Result<String> {
    if raw.is_empty() || raw.len() > 253 {
        return Err(AetherError::Other("invalid SOCKS domain length".into()));
    }
    if !raw.is_ascii() {
        return Err(AetherError::Other("non-ASCII SOCKS domain".into()));
    }
    let name = String::from_utf8(raw.to_vec())
        .map_err(|_| AetherError::Other("invalid SOCKS domain encoding".into()))?;
    if !name.split('.').all(|l| !l.is_empty() && l.len() <= 63) {
        return Err(AetherError::Other("invalid SOCKS domain label".into()));
    }
    Ok(name)
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
            Target::Domain(parse_domain_name(&name)?)
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

fn is_ipv4_only() -> bool {
    matches!(
        crate::runtime_env::var("AETHER_IP")
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase()
            .as_str(),
        "4" | "v4" | "ipv4"
    )
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
///
/// `pub(crate)` because the TUN path has to set the *same* resolvers on the
/// adapter that the in-tunnel stub resolver forwards to; two sources of truth
/// here meant the proxy honoured `AETHER_DNS` while TUN silently ignored it.
pub(crate) fn configured_dns_servers() -> Vec<SocketAddr> {
    let raw = crate::runtime_env::var("AETHER_DNS").unwrap_or_default();
    parse_dns_servers(&raw)
}

/// Resolvers to pin on the tunnel adapter, from the list the in-tunnel stub
/// forwards to.
///
/// Hardcoded `'1.1.1.1','1.0.0.1'` here meant a user's `AETHER_DNS` — a local
/// resolver, an internal box, a filtering one — was honoured by the proxy path and
/// silently discarded by TUN, and the *restore* path then reset the adapter to
/// "whatever DHCP says" rather than to what it had been.
///
/// IPv4 only: the adapter's IPv6 binding is disabled just above, and a
/// mixed-family `-ServerAddresses` call fails outright.
/// `pub` rather than `pub(crate)` on purpose: its only caller is the Windows TUN
/// path, and a crate-private helper used by exactly one `#[cfg(windows)]` module is
/// dead code — and therefore a hard `-D warnings` failure — on every other target,
/// including the Linux CI that runs this module's tests.
pub fn dns_servers_for_adapter(list: &[SocketAddr]) -> Vec<Ipv4Addr> {
    let mut out: Vec<Ipv4Addr> = Vec::new();
    for sa in list {
        if let IpAddr::V4(v4) = sa.ip() {
            if !out.contains(&v4) {
                out.push(v4);
            }
        }
        if out.len() >= 4 {
            break;
        }
    }
    if out.is_empty() {
        // A configured list of nothing but IPv6 resolvers must still leave the
        // adapter able to resolve: defaults beat an empty list.
        out.push(Ipv4Addr::new(1, 1, 1, 1));
        out.push(Ipv4Addr::new(1, 0, 0, 1));
    }
    out
}

fn valid_dns_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 253
        && name.split('.').all(|l| !l.is_empty() && l.len() <= 63)
}

pub async fn dns_resolve(stack: &StackHandle, name: &str) -> Result<IpAddr> {
    let key = name.to_ascii_lowercase();
    {
        // `parking_lot` has no poison state: with `std::sync::Mutex` a panic
        // under this guard made `lock()` an `Err` forever, so every later
        // lookup silently missed the cache and re-resolved over the tunnel.
        let mut guard = dns_cache().lock();
        if let Some((ip, first, used)) = guard.map.get_mut(&key) {
            if first.elapsed() < DNS_CACHE_TTL {
                *used = Instant::now();
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
            let (qid, query) = build_dns_query(name, qtype)?;
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
                {
                    let now = Instant::now();
                    let mut guard = dns_cache().lock();
                    guard.map.insert(key, (ip, now, now));
                    evict_lru(&mut guard);
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

fn build_dns_query(name: &str, qtype: u16) -> Result<(u16, Vec<u8>)> {
    let mut q = Vec::with_capacity(32 + name.len());
    let id: u16 = rand::random();
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&[0x01, 0x00]);
    q.extend_from_slice(&[0x00, 0x01]);
    q.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    for label in name.split('.') {
        if label.is_empty() || label.len() > 63 {
            // Dropping the label would ask for `example.com` when the client
            // asked for `<64+-byte-label>.example.com`.
            return Err(AetherError::Other(format!(
                "cannot encode DNS label {:?} (empty or longer than 63 bytes)",
                label
            )));
        }
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0x00);
    q.extend_from_slice(&qtype.to_be_bytes());
    q.extend_from_slice(&[0x00, 0x01]);
    Ok((id, q))
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

    if ip.is_ipv6() && is_ipv4_only() {
        let _ = reply(&mut sock, REP_ATYP_NOT_SUPPORTED).await;
        return Err(AetherError::Other("IPv6 target rejected in IPv4-only mode".into()));
    }

    let dst = SocketAddr::new(ip, port);
    // Belt-and-braces around the smoltcp socket connect-timeout (netstack): a
    // caller-side bound guarantees the client gets a SOCKS error reply instead
    // of hanging even if some other stall keeps the socket from resolving.
    // IPv6 connections use a tighter 3s bound to avoid stalling Happy Eyeballs.
    let connect_deadline = if ip.is_ipv6() {
        Duration::from_secs(3)
    } else {
        Duration::from_secs(20)
    };
    let conn = match tokio::time::timeout(connect_deadline, stack.open_tcp(dst)).await {
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

    // Report the address the client is actually talking to. `0.0.0.0:0` is a
    // placeholder clients that read BND.ADDR (some UDP-over-SOCKS stacks) take
    // literally and then fail to send.
    let bound = sock.local_addr().unwrap_or_else(|_| ([0, 0, 0, 0], 0).into());
    reply_bound(&mut sock, bound).await?;

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
    let routes: Arc<Mutex<HashMap<SocketAddr, (SocketAddr, Instant)>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let resolver_routes = routes.clone();
    tokio::spawn(async move {
        while let Some((name, port, payload, from)) = res_rx.recv().await {
            match tokio::time::timeout(Duration::from_secs(4), dns_resolve(&stack, &name)).await {
                Ok(Ok(ip)) => {
                    let dst = SocketAddr::new(ip, port);
                    {
                        let mut map = resolver_routes.lock();
                        note_origin(&mut map, dst, from);
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
                        if ip.is_ipv6() && is_ipv4_only() {
                            continue;
                        }
                        let dst = SocketAddr::new(ip, payload.0);
                        {
                            let mut map = routes.lock();
                            note_origin(&mut map, dst, from);
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
                // Reply filtering, not forwarding: a datagram from a peer the
                // client never sent to is dropped. The previous `.or(client)`
                // handed the client *anything* that arrived, labelled with the
                // attacker-chosen source address.
                let target_client = {
                    let mut map = routes.lock();
                    match map.get_mut(&src) {
                        Some((from, seen)) if seen.elapsed() < UDP_ORIGIN_TTL => {
                            *seen = Instant::now();
                            Some(*from)
                        }
                        Some(_) => {
                            map.remove(&src);
                            None
                        }
                        None => None,
                    }
                };
                if target_client.is_none() {
                    log::debug!("socks udp: dropping unsolicited datagram from {src}");
                }
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
    // RFC 1928 §7: two reserved zero bytes, then FRAG which must be 0.
    if buf.len() < 4 || buf[0] != 0 || buf[1] != 0 || buf[2] != 0 {
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
            let name = parse_domain_name(&buf[pos..pos + len]).ok()?;
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

/// Record that the client just talked to `dst`, so replies may come back, and
/// keep the table bounded by age rather than by wiping every flow at once
/// (`clear()` dropped thousands of live origins on a burst).
fn note_origin(map: &mut HashMap<SocketAddr, (SocketAddr, Instant)>, dst: SocketAddr, from: SocketAddr) {
    let now = Instant::now();
    map.insert(dst, (from, now));
    if map.len() <= UDP_ORIGIN_MAX {
        return;
    }
    map.retain(|_, (_, seen)| seen.elapsed() < UDP_ORIGIN_TTL);
    if map.len() > UDP_ORIGIN_MAX {
        // Still over budget: the oldest half goes, newest conversations stay.
        let mut by_age: Vec<(Instant, SocketAddr)> =
            map.iter().map(|(k, (_, v))| (*v, *k)).collect();
        by_age.sort_unstable_by_key(|(seen, _)| *seen);
        for (_, key) in by_age.iter().take(by_age.len() - UDP_ORIGIN_MAX / 2) {
            map.remove(key);
        }
    }
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
    use super::{
        build_dns_query, decode_qname, evict_lru, note_origin, parse_dns_answer_id, parse_domain_name,
        parse_udp_request, select_auth_method, DnsCache, DNS_CACHE_MAX, UDP_ORIGIN_MAX,
    };
    use std::{
        collections::HashMap,
        net::{IpAddr, SocketAddr},
        time::{Duration, Instant},
    };

    /// The TUN path used to hardcode `1.1.1.1`/`1.0.0.1` on the adapter while the
    /// proxy path honoured `AETHER_DNS`, so the same setting worked in one mode
    /// and was discarded in the other — for a user on a filtering or internal
    /// resolver, the tunnel then silently bypassed it.
    #[test]
    fn adapter_resolvers_come_from_the_configured_list() {
        use super::{dns_servers_for_adapter, parse_dns_servers};
        let list = parse_dns_servers("9.9.9.9, 1.0.0.1, 9.9.9.9, [2606:4700:4700::1111]");
        let got = dns_servers_for_adapter(&list);
        assert_eq!(
            got,
            vec![
                std::net::Ipv4Addr::new(9, 9, 9, 9),
                std::net::Ipv4Addr::new(1, 0, 0, 1)
            ],
            "order preserved, duplicates dropped, IPv6 excluded (the adapter has no v6 binding)"
        );

        // IPv6-only configuration must still leave the adapter able to resolve.
        let v6only = parse_dns_servers("2606:4700:4700::1111");
        assert_eq!(
            dns_servers_for_adapter(&v6only),
            vec![
                std::net::Ipv4Addr::new(1, 1, 1, 1),
                std::net::Ipv4Addr::new(1, 0, 0, 1)
            ]
        );

        // Windows accepts a bounded list; more than that is not silently truncated
        // in a way that reorders what the user asked for.
        let many = parse_dns_servers("10.0.0.1,10.0.0.2,10.0.0.3,10.0.0.4,10.0.0.5");
        assert_eq!(dns_servers_for_adapter(&many).len(), 4);
    }

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

    /// `clear()` at the cap wiped every live origin at once, so an in-flight
    /// QUIC connection suddenly had no permitted peer to reply to.
    #[test]
    fn origin_table_ages_out_instead_of_wiping_every_flow() {
        let client = SocketAddr::from(([127, 0, 0, 1], 5150));
        let peer = |i: usize| {
            SocketAddr::new(IpAddr::from([1, 2, (i / 251) as u8, (i % 251) as u8]), 443)
        };
        let mut map: HashMap<SocketAddr, (SocketAddr, Instant)> = HashMap::new();
        for i in 0..UDP_ORIGIN_MAX + 500 {
            map.insert(peer(i), (client, Instant::now()));
        }
        assert!(map.len() > UDP_ORIGIN_MAX);
        note_origin(&mut map, peer(UDP_ORIGIN_MAX + 500), client);
        assert!(
            map.len() <= UDP_ORIGIN_MAX,
            "origin table still over budget: {}",
            map.len()
        );
        assert!(
            map.contains_key(&peer(UDP_ORIGIN_MAX + 500)),
            "the newest origin must survive eviction"
        );
        assert!(
            map.len() >= UDP_ORIGIN_MAX / 2,
            "eviction wiped live flows instead of ageing entries out"
        );
    }

    /// The old builder `continue`d past an over-long label, so a client asking
    /// for `<65-byte-label>.example.com` got `example.com` connected — a
    /// different host, reported as success.
    #[test]
    fn query_builder_refuses_names_it_cannot_encode() {
        let long_label = "a".repeat(64);
        assert!(build_dns_query(&format!("{long_label}.example.com"), 1).is_err());
        assert!(build_dns_query("example..com", 1).is_err());
        assert!(build_dns_query("", 1).is_err());

        let (_, q) = build_dns_query("www.example.com", 1).unwrap();
        // Header is 12 bytes; then length-prefixed labels, root, qtype, qclass.
        assert_eq!(&q[12..16], &[3, b'w', b'w', b'w']);
        assert_eq!(&q[16..24], &[7, b'e', b'x', b'a', b'm', b'p', b'l', b'e']);
        assert_eq!(&q[24..28], &[3, b'c', b'o', b'm']);
        assert_eq!(q[28], 0);
    }

    #[test]
    fn wire_domains_are_validated_not_lossy_decoded() {
        assert!(parse_domain_name(b"example.com").is_ok());
        assert!(parse_domain_name("exämple.com".as_bytes()).is_err());
        assert!(parse_domain_name(b"").is_err());
        assert!(parse_domain_name(b"example..com").is_err());
        assert!(parse_domain_name("a".repeat(254).as_bytes()).is_err());
    }

    #[test]
    fn udp_relay_header_requires_reserved_zeroes() {
        let mut hdr = vec![0x00, 0x00, 0x00, 0x01, 93, 184, 216, 34, 1, 187];
        let payload = b"hi".to_vec();
        hdr.extend_from_slice(&payload);
        assert!(parse_udp_request(&hdr).is_some());

        for bad in [0usize, 1, 2] {
            let mut mangled = hdr.clone();
            mangled[bad] = 0xAA;
            assert!(
                parse_udp_request(&mangled).is_none(),
                "byte {bad} of the SOCKS5 UDP header is reserved/FRAG and must be zero"
            );
        }
    }

    /// `retain(ttl)` at the cap evicted nothing while the TTL was still live, so
    /// a wildcard-DNS page grew the cache without bound.
    #[test]
    fn dns_cache_evicts_least_recently_used() {
        let base = Instant::now();
        let addr = IpAddr::from([93, 184, 216, 34]);
        let mut cache = DnsCache { map: HashMap::new() };
        for i in 0..DNS_CACHE_MAX + 100 {
            let first = base - Duration::from_secs(5);
            // Higher index == touched more recently; key 0 is stale by 10 s.
            let used = if i == 0 {
                base - Duration::from_secs(10)
            } else {
                base + Duration::from_micros(i as u64)
            };
            cache.map.insert(format!("host{i}.example.com"), (addr, first, used));
        }
        assert!(cache.map.len() > DNS_CACHE_MAX);
        evict_lru(&mut cache);
        assert!(
            cache.map.len() <= DNS_CACHE_MAX,
            "cache still over budget after eviction: {}",
            cache.map.len()
        );
        assert!(
            !cache.map.contains_key("host0.example.com"),
            "eviction must remove the least-recently-used entry first"
        );
        assert!(cache.map.contains_key(&format!("host{DNS_CACHE_MAX}.example.com")));
    }
}
