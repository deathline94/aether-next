use std::net::SocketAddr;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::error::{AetherError, Result};
use crate::netstack::{StackHandle, TcpConn};
use crate::socks;

const MAX_HEADER: usize = 16 * 1024;
const MAX_CLIENTS: usize = 256;
const MAX_REQUEST_LINE: usize = 4096;
const MAX_SESSION: std::time::Duration = std::time::Duration::from_secs(4 * 60 * 60);

pub async fn bind(listen: SocketAddr) -> Result<TcpListener> {
    if !listen.ip().is_loopback() && std::env::var_os("AETHER_UNSAFE_PUBLIC_PROXY").is_none() {
        return Err(AetherError::Other("refusing non-loopback HTTP proxy bind".into()));
    }
    Ok(TcpListener::bind(listen).await?)
}

pub async fn serve_listener(listener: TcpListener, stack: StackHandle) -> Result<()> {
    let listen = listener.local_addr()?;
    log::info!("[+] http proxy listening on {listen}");
    let permits = std::sync::Arc::new(tokio::sync::Semaphore::new(MAX_CLIENTS));
    loop {
        let (socket, peer) = listener.accept().await?;
        let permit = match permits.clone().try_acquire_owned() { Ok(p) => p, Err(_) => continue };
        let _ = socket.set_nodelay(true);
        let stack = stack.clone();
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(error) = tokio::time::timeout(MAX_SESSION, handle(socket, stack)).await
                .map_err(|_| AetherError::Other("HTTP maximum session duration reached".into())).and_then(|r| r) {
                log::debug!("http proxy client {peer} ended: {error}");
            }
        });
    }
}

async fn handle(mut client: TcpStream, stack: StackHandle) -> Result<()> {
    let header = read_header(&mut client).await?;
    let header_end =
        find_header_end(&header).ok_or_else(|| AetherError::Other("invalid HTTP header".into()))?;
    let text = std::str::from_utf8(&header[..header_end])
        .map_err(|_| AetherError::Other("invalid HTTP header".into()))?;
    let first = text
        .lines()
        .next()
        .ok_or_else(|| AetherError::Other("empty HTTP request".into()))?;
    if first.len() > MAX_REQUEST_LINE { return Err(AetherError::Other("HTTP request line too long".into())); }
    let mut request = first.split_whitespace();
    let method = request.next().unwrap_or("");
    let target = request.next().unwrap_or("");

    let (host, port) = if method.eq_ignore_ascii_case("CONNECT") {
        parse_authority(target, 443)?
    } else if let Some(authority) = target.strip_prefix("http://") {
        parse_authority(authority.split('/').next().unwrap_or(""), 80)?
    } else {
        // HTTP header names are case-insensitive (RFC 9110); match any spelling
        // of Host instead of only the two common capitalizations.
        let host = text
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                if name.trim().eq_ignore_ascii_case("host") {
                    Some(value.trim().to_string())
                } else {
                    None
                }
            })
            .ok_or_else(|| AetherError::Other("HTTP Host header missing".into()))?;
        parse_authority(&host, 80)?
    };

    let ip = match socks::resolve_host(&stack, &host).await {
        Ok(ip) => ip,
        Err(error) => {
            // Consistency fix: resolution failures previously dropped the
            // connection with no HTTP response at all while upstream-connect
            // failures returned a 502. Answer 502 for both.
            let _ = client
                .write_all(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")
                .await;
            return Err(error);
        }
    };
    let dst = SocketAddr::new(ip, port);
    let upstream = match tokio::time::timeout(
        std::time::Duration::from_secs(20),
        stack.open_tcp(dst),
    )
    .await
    {
        Ok(Ok(value)) => value,
        Ok(Err(error)) => {
            let _ = client
                .write_all(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")
                .await;
            return Err(error);
        }
        Err(_) => {
            let _ = client
                .write_all(b"HTTP/1.1 504 Gateway Timeout\r\nConnection: close\r\n\r\n")
                .await;
            return Err(AetherError::Other("upstream connect timed out".into()));
        }
    };

    if method.eq_ignore_ascii_case("CONNECT") {
        client
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;
        if header_end < header.len() {
            // The 200 is already on the wire, so a failure to forward pipelined
            // early data must not surface as a command error — just close.
            if upstream.send(header[header_end..].to_vec()).await.is_err() {
                let _ = client.shutdown().await;
                return Ok(());
            }
        }
    } else {
        match rewrite_absolute_uri(header) {
            Ok(rewritten) => {
                if upstream.send(rewritten).await.is_err() {
                    let _ = client.shutdown().await;
                    return Ok(());
                }
            }
            Err(e) => {
                let _ = client
                    .write_all(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")
                    .await;
                return Err(e);
            }
        }
    }
    relay(client, upstream).await
}

fn find_header_end(header: &[u8]) -> Option<usize> {
    header
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|at| at + 4)
}

async fn read_header(stream: &mut TcpStream) -> Result<Vec<u8>> {
    let mut header = Vec::with_capacity(2048);
    let mut buf = [0u8; 2048];
    loop {
        let count = tokio::time::timeout(std::time::Duration::from_secs(10), stream.read(&mut buf))
            .await
            .map_err(|_| AetherError::Other("HTTP header read timeout".into()))??;
        if count == 0 {
            return Err(AetherError::Other(
                "client closed before HTTP header".into(),
            ));
        }
        header.extend_from_slice(&buf[..count]);
        if header.windows(4).any(|window| window == b"\r\n\r\n") {
            return Ok(header);
        }
        if header.len() >= MAX_HEADER {
            return Err(AetherError::Other("HTTP header too large".into()));
        }
    }
}

fn parse_authority(value: &str, default_port: u16) -> Result<(String, u16)> {
    let value = value.trim();
    // Strip userinfo if present: user:pass@host:port
    let value = value.rsplit_once('@').map(|(_, h)| h).unwrap_or(value);
    if let Ok(addr) = value.parse::<SocketAddr>() {
        return Ok((addr.ip().to_string(), addr.port()));
    }
    // RFC 3986: an empty port after ':' is equivalent to the default port.
    fn port_after(rest: &str, default_port: u16) -> Result<Option<u16>> {
        let Some(port_str) = rest.strip_prefix(':') else {
            return Ok(None);
        };
        if port_str.trim().is_empty() {
            return Ok(Some(default_port));
        }
        port_str
            .trim()
            .parse()
            .map(Some)
            .map_err(|_| AetherError::Other("invalid proxy port".into()))
    }
    if value.starts_with('[') {
        if let Some(end) = value.find(']') {
            let host = &value[1..end];
            let rest = &value[end + 1..];
            if let Some(port) = port_after(rest, default_port)? {
                return Ok((host.to_string(), port));
            }
            return Ok((host.to_string(), default_port));
        }
    }
    if let Some((host, port_str)) = value.rsplit_once(':') {
        if !host.contains(':') {
            let port = if port_str.trim().is_empty() {
                default_port
            } else {
                port_str
                    .trim()
                    .parse()
                    .map_err(|_| AetherError::Other("invalid proxy port".into()))?
            };
            return Ok((host.to_string(), port));
        }
    }
    if value.is_empty() {
        return Err(AetherError::Other("proxy target missing".into()));
    }
    Ok((value.to_string(), default_port))
}

fn rewrite_absolute_uri(mut header: Vec<u8>) -> Result<Vec<u8>> {
    let end = header
        .windows(2)
        .position(|window| window == b"\r\n")
        .ok_or_else(|| AetherError::Other("invalid HTTP request line".into()))?;
    let first = std::str::from_utf8(&header[..end])
        .map_err(|_| AetherError::Other("invalid HTTP request line".into()))?;
    let mut parts = first.split_whitespace();
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("");
    let version = parts.next().unwrap_or("HTTP/1.1");
    if let Some(rest) = target.strip_prefix("http://") {
        let path = rest.find('/').map(|at| &rest[at..]).unwrap_or("/");
        let replacement = format!("{method} {path} {version}");
        header.splice(..end, replacement.bytes());
    }
    Ok(header)
}

async fn relay(client: TcpStream, upstream: TcpConn) -> Result<()> {
    const RELAY: usize = 256 * 1024;
    let (sender, mut from_stack) = upstream.into_split();
    let (mut reader, mut writer) = client.into_split();
    let upload = tokio::spawn(async move {
        let mut buf = vec![0u8; RELAY];
        loop {
            match reader.read(&mut buf).await {
                Ok(0) | Err(_) => {
                    sender.close().await;
                    break;
                }
                Ok(count) if sender.send(buf[..count].to_vec()).await.is_err() => break,
                Ok(_) => {}
            }
        }
    });
    while let Some(first) = from_stack.recv().await {
        let mut batch = first;
        while batch.len() < RELAY {
            match from_stack.try_recv() {
                Ok(more) => batch.extend_from_slice(&more),
                Err(_) => break,
            }
        }
        if writer.write_all(&batch).await.is_err() {
            break;
        }
    }
    let _ = writer.shutdown().await;
    upload.abort();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::find_header_end;

    #[test]
    fn separates_pipelined_connect_payload() {
        let request = b"CONNECT example.com:443 HTTP/1.1\r\n\r\nTLS";
        let end = find_header_end(request).unwrap();
        assert_eq!(&request[end..], b"TLS");
    }
}
