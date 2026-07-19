use std::net::SocketAddr;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::error::{AetherError, Result};
use crate::netstack::{StackHandle, TcpConn};
use crate::socks;

const MAX_HEADER: usize = 64 * 1024;

pub async fn serve(listen: SocketAddr, stack: StackHandle) -> Result<()> {
    serve_listener(bind(listen).await?, stack).await
}

pub async fn bind(listen: SocketAddr) -> Result<TcpListener> {
    Ok(TcpListener::bind(listen).await?)
}

pub async fn serve_listener(listener: TcpListener, stack: StackHandle) -> Result<()> {
    let listen = listener.local_addr()?;
    log::info!("[+] http proxy listening on {listen}");
    loop {
        let (socket, peer) = listener.accept().await?;
        let _ = socket.set_nodelay(true);
        let stack = stack.clone();
        tokio::spawn(async move {
            if let Err(error) = handle(socket, stack).await {
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
    let mut request = first.split_whitespace();
    let method = request.next().unwrap_or("");
    let target = request.next().unwrap_or("");

    let (host, port) = if method.eq_ignore_ascii_case("CONNECT") {
        parse_authority(target, 443)?
    } else if let Some(authority) = target.strip_prefix("http://") {
        parse_authority(authority.split('/').next().unwrap_or(""), 80)?
    } else {
        let host = text
            .lines()
            .find_map(|line| {
                line.strip_prefix("Host:")
                    .or_else(|| line.strip_prefix("host:"))
            })
            .map(str::trim)
            .ok_or_else(|| AetherError::Other("HTTP Host header missing".into()))?;
        parse_authority(host, 80)?
    };

    let ip = socks::resolve_host(&stack, &host).await?;
    let upstream = stack.open_tcp(SocketAddr::new(ip, port)).await;
    let upstream = match upstream {
        Ok(value) => value,
        Err(error) => {
            let _ = client
                .write_all(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")
                .await;
            return Err(error);
        }
    };

    if method.eq_ignore_ascii_case("CONNECT") {
        client
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;
        if header_end < header.len() {
            upstream.send(header[header_end..].to_vec()).await?;
        }
    } else {
        upstream.send(rewrite_absolute_uri(header)?).await?;
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
        let count = stream.read(&mut buf).await?;
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
    if let Ok(addr) = value.parse::<SocketAddr>() {
        return Ok((addr.ip().to_string(), addr.port()));
    }
    if let Some((host, port)) = value.rsplit_once(':') {
        if !host.contains(':') {
            return Ok((
                host.to_string(),
                port.parse()
                    .map_err(|_| AetherError::Other("invalid proxy port".into()))?,
            ));
        }
    }
    let host = value.trim_matches(['[', ']']);
    if host.is_empty() {
        return Err(AetherError::Other("proxy target missing".into()));
    }
    Ok((host.to_string(), default_port))
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
