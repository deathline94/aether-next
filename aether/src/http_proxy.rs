use std::net::SocketAddr;

use base64::Engine;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::error::{AetherError, Result};
use crate::netstack::{StackHandle, TcpConn};
use crate::socks;

pub const MAX_HEADER: usize = 16 * 1024;
const MAX_REQUEST_LINE: usize = 4096;

pub async fn bind(listen: SocketAddr) -> Result<TcpListener> {
    // Centralised in `engine_config` (one knob for whether a remote-facing proxy
    // may bind at all) plus `socks::check_listener_bind`: a listener that *is*
    // allowed to face outward must be able to authenticate its clients.
    socks::check_listener_bind(listen)?;
    Ok(TcpListener::bind(listen).await?)
}

/// The answer a client gets when the proxy is at its session limit (T163).
///
/// Before this the accepted socket was dropped unseen, so the browser reported a
/// network error and the user had no way to learn that a cap had been reached.
pub fn over_capacity_reply() -> Vec<u8> {
    b"HTTP/1.1 503 Service Unavailable\r\nRetry-After: 5\r\nConnection: close\r\n\r\n".to_vec()
}

fn auth_required_reply() -> Vec<u8> {
    b"HTTP/1.1 407 Proxy Authentication Required\r\n\
      Proxy-Authenticate: Basic realm=\"aether\"\r\n\
      Connection: close\r\n\r\n"
        .to_vec()
}

/// Value of a header, by case-insensitive name (RFC 9110).
fn header_value<'a>(text: &'a str, name: &str) -> Option<&'a str> {
    text.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        key.trim().eq_ignore_ascii_case(name).then(|| value.trim())
    })
}

/// Decode a `Proxy-Authorization: Basic base64(user:pass)` value.
fn basic_credentials(value: &str) -> Option<(String, String)> {
    let (scheme, encoded) = value.split_once(char::is_whitespace)?;
    if !scheme.eq_ignore_ascii_case("Basic") {
        return None;
    }
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded.trim())
        .ok()?;
    let text = std::str::from_utf8(&decoded).ok()?;
    let (user, pass) = text.split_once(':')?;
    Some((user.to_string(), pass.to_string()))
}

/// True when the request block carries proxy credentials that match.
fn proxy_auth_ok(header_text: &str, want: &(String, String)) -> bool {
    let Some(value) = header_value(header_text, "proxy-authorization") else {
        return false;
    };
    match basic_credentials(value) {
        Some((user, pass)) => {
            let u = socks::secret_eq(user.as_bytes(), want.0.as_bytes());
            // Both halves are compared unconditionally: a password is not
            // guessable by watching where the check stops.
            let p = socks::secret_eq(pass.as_bytes(), want.1.as_bytes());
            u && p
        }
        None => false,
    }
}

pub async fn serve_listener(listener: TcpListener, stack: StackHandle) -> Result<()> {
    let listen = listener.local_addr()?;
    log::info!("[+] http proxy listening on {listen}");
    let permits = std::sync::Arc::new(tokio::sync::Semaphore::new(socks::MAX_CLIENTS));
    // Same policy as the SOCKS listener: a client that races its own connect must
    // not be allowed to end the tunnel. `session.rs` watches this future's `Err`
    // as "the http proxy exited" and tears the session down on it.
    let mut transient = 0u32;
    loop {
        let (socket, peer) = match listener.accept().await {
            Ok(v) => {
                transient = 0;
                v
            }
            Err(e)
                if socks::is_transient_accept(&e) && transient < socks::MAX_TRANSIENT_ACCEPTS =>
            {
                transient += 1;
                log::warn!(
                    "[http] accept failed ({e}); staying up ({transient}/{})",
                    socks::MAX_TRANSIENT_ACCEPTS
                );
                tokio::time::sleep(socks::ACCEPT_BACKOFF).await;
                continue;
            }
            Err(e) => return Err(e.into()),
        };
        let permit = match permits.clone().try_acquire_owned() {
            Ok(p) => p,
            // T163: an explicit, protocol-level refusal instead of a dropped
            // socket, answered off the accept loop so a slow client cannot stall it.
            Err(_) => {
                log::warn!(
                    "http proxy at the {}-session limit; refusing {peer}",
                    socks::MAX_CLIENTS
                );
                tokio::spawn(async move {
                    let _ = refuse_over_capacity(socket).await;
                });
                continue;
            }
        };
        let _ = socket.set_nodelay(true);
        let stack = stack.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let outcome = tokio::time::timeout(socks::MAX_SESSION, handle(socket, stack)).await;
            let session = match outcome {
                Ok(r) => r,
                Err(_) => {
                    let msg = socks::session_cap_message("http proxy", socks::MAX_SESSION);
                    log::warn!("{msg} (peer {peer})");
                    return Err(AetherError::Other(msg));
                }
            };
            if let Err(error) = session {
                log::debug!("http proxy client {peer} ended: {error}");
            }
            Ok(())
        });
    }
}

async fn refuse_over_capacity(mut client: TcpStream) -> Result<()> {
    let wrote = tokio::time::timeout(std::time::Duration::from_secs(10), async move {
        client.write_all(&over_capacity_reply()).await?;
        client.shutdown().await?;
        Ok::<(), std::io::Error>(())
    })
    .await;
    match wrote {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => Err(AetherError::Other(format!(
            "http refusal write failed: {e}"
        ))),
        Err(_) => Err(AetherError::Other("http refusal write timed out".into())),
    }
}

/// One boundary rule: the header block must be CRLF-delimited throughout.
///
/// `str::lines()` (used to pick the request line and the `Host` header) also
/// accepts a bare LF, while the URI rewrite locates the request line by `\r\n`.
/// A client that mixed the two therefore made the proxy read one request
/// locally and forward a different one: `GET http://a/\nHost: b\r\n\r\n` had its
/// first *two* lines replaced by the rewritten request line, dropping the Host
/// header the upstream would otherwise have honoured.
fn assert_strict_crlf(block: &[u8]) -> Result<()> {
    let mut i = 0;
    while i < block.len() {
        match block[i] {
            b'\r' => {
                if block.get(i + 1) != Some(&b'\n') {
                    return Err(AetherError::Other("HTTP header: bare CR".into()));
                }
                i += 2;
            }
            b'\n' => return Err(AetherError::Other("HTTP header: bare LF".into())),
            b'\0' => return Err(AetherError::Other("HTTP header: NUL byte".into())),
            _ => i += 1,
        }
    }
    Ok(())
}

async fn handle(mut client: TcpStream, stack: StackHandle) -> Result<()> {
    let header = read_header(&mut client).await?;
    let header_end =
        find_header_end(&header).ok_or_else(|| AetherError::Other("invalid HTTP header".into()))?;
    assert_strict_crlf(&header[..header_end])?;
    let text = std::str::from_utf8(&header[..header_end])
        .map_err(|_| AetherError::Other("invalid HTTP header".into()))?;
    // Credentials, if configured, are checked before a single byte is relayed:
    // the listener may be reachable by others, and nothing here should be
    // resolved or connected on their behalf (T157).
    if let Some(want) = socks::proxy_credentials() {
        if !proxy_auth_ok(text, &want) {
            let _ = client.write_all(&auth_required_reply()).await;
            return Err(AetherError::Other(
                "http proxy authentication required".into(),
            ));
        }
    }
    let first = text
        .lines()
        .next()
        .ok_or_else(|| AetherError::Other("empty HTTP request".into()))?;
    if first.len() > MAX_REQUEST_LINE {
        return Err(AetherError::Other("HTTP request line too long".into()));
    }
    // `split_whitespace` would also fold a tab or vertical space into a
    // separator, so a request line is only ever three SP-delimited tokens.
    let mut request = first.split(' ');
    let method = request.next().unwrap_or("");
    let target = request.next().unwrap_or("");
    let version = request.next().unwrap_or("");
    if request.next().is_some()
        || method.is_empty()
        || target.is_empty()
        || !(version.eq_ignore_ascii_case("HTTP/1.1") || version.eq_ignore_ascii_case("HTTP/1.0"))
    {
        return Err(AetherError::Other("malformed HTTP request line".into()));
    }

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
    let upstream =
        match tokio::time::timeout(std::time::Duration::from_secs(20), stack.open_tcp(dst)).await {
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

pub async fn read_header(stream: &mut TcpStream) -> Result<Vec<u8>> {
    let mut header = Vec::with_capacity(2048);
    let mut buf = [0u8; 2048];
    loop {
        let remaining = MAX_HEADER.saturating_sub(header.len());
        if remaining == 0 {
            return Err(AetherError::Other("HTTP header too large".into()));
        }
        let to_read = buf.len().min(remaining);
        let count = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            stream.read(&mut buf[..to_read]),
        )
        .await
        .map_err(|_| AetherError::Other("HTTP header read timeout".into()))??;

        if count == 0 {
            return Err(AetherError::Other(
                "client closed before HTTP header".into(),
            ));
        }
        header.extend_from_slice(&buf[..count]);
        if let Some(pos) = header.windows(4).position(|window| window == b"\r\n\r\n") {
            if pos + 4 > MAX_HEADER {
                return Err(AetherError::Other("HTTP header too large".into()));
            }
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
    let mut parts = first.split(' ');
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("");
    let version = parts.next().unwrap_or("HTTP/1.1");
    // Defence in depth: this function splices `..end`, so it must never be
    // handed a "request line" that swallowed a header, and no control character
    // may sit inside the three space-delimited tokens.
    if first.chars().any(char::is_control)
        || method.is_empty()
        || target.is_empty()
        || parts.next().is_some()
    {
        return Err(AetherError::Other("invalid HTTP request line".into()));
    }
    if target.len() >= 7 && target[..7].eq_ignore_ascii_case("http://") {
        let rest = &target[7..];
        let authority_end = match (rest.find('/'), rest.find('?')) {
            (Some(slash), Some(q)) => Some(slash.min(q)),
            (Some(slash), None) => Some(slash),
            (None, Some(q)) => Some(q),
            (None, None) => None,
        };
        let path = match authority_end {
            Some(idx) if rest.as_bytes()[idx] == b'?' => format!("/{}", &rest[idx..]),
            Some(idx) => rest[idx..].to_string(),
            None => "/".to_string(),
        };
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
    use super::{
        assert_strict_crlf, auth_required_reply, basic_credentials, find_header_end, header_value,
        over_capacity_reply, proxy_auth_ok, rewrite_absolute_uri,
    };

    /// The session-limit refusal has to be a real HTTP response (T163): the old
    /// behaviour was to drop the accepted socket, which a browser reported as an
    /// unreachable proxy with no hint that a cap had been hit.
    #[test]
    fn over_capacity_reply_is_a_well_formed_refusal() {
        let reply = over_capacity_reply();
        let text = String::from_utf8(reply.clone()).expect("ascii");
        assert!(text.starts_with("HTTP/1.1 503 "), "{text}");
        assert!(
            text.contains("Connection: close\r\n"),
            "must not be kept alive"
        );
        assert!(
            text.ends_with("\r\n\r\n"),
            "a header block ends at a blank line"
        );
        assert!(text.contains("Retry-After"), "and says when to try again");
        let auth = String::from_utf8(auth_required_reply()).expect("ascii");
        assert!(auth.starts_with("HTTP/1.1 407 "), "{auth}");
        assert!(auth.contains("Proxy-Authenticate: Basic"), "{auth}");
    }

    #[test]
    fn header_lookup_ignores_case_and_surrounding_space() {
        let block = "GET http://a/ HTTP/1.1\r\nhost:  A.example \r\nAccept: */*\r\n\r\n";
        assert_eq!(header_value(block, "host"), Some("A.example"));
        assert_eq!(header_value(block, "accept"), Some("*/*"));
        assert_eq!(header_value(block, "proxy-authorization"), None);
    }

    #[test]
    fn basic_credentials_decode_and_are_matched_exactly() {
        // base64("u:p") == "dTpw"
        let ok = "GET http://a/ HTTP/1.1\r\nProxy-Authorization: Basic dTpw\r\n\r\n";
        let want = ("u".to_string(), "p".to_string());
        assert!(proxy_auth_ok(ok, &want));
        assert!(!proxy_auth_ok(ok, &("u".to_string(), "q".to_string())));
        assert!(!proxy_auth_ok(ok, &("v".to_string(), "p".to_string())));
        // No header at all, and a header we cannot parse, both fail closed.
        assert!(!proxy_auth_ok("GET http://a/ HTTP/1.1\r\n\r\n", &want));
        assert!(!proxy_auth_ok(
            "GET http://a/ HTTP/1.1\r\nProxy-Authorization: Bearer dTpw\r\n\r\n",
            &want
        ));
        assert!(!proxy_auth_ok(
            "GET http://a/ HTTP/1.1\r\nProxy-Authorization: Basic !!!not-base64\r\n\r\n",
            &want
        ));
        // Scheme name is case-insensitive (RFC 7235); the credentials are not.
        assert!(proxy_auth_ok(
            "GET http://a/ HTTP/1.1\r\nproxy-authorization: basic dTpw\r\n\r\n",
            &want
        ));
        let (user, pass) = basic_credentials("Basic dTpw").expect("decodes");
        assert_eq!((user.as_str(), pass.as_str()), ("u", "p"));
        // The split is on the *first* colon, so a password may contain one.
        let (user, pass) = basic_credentials("Basic dTpwYXNzOndvcmQ=").expect("decodes");
        assert_eq!((user.as_str(), pass.as_str()), ("u", "pass:word"));
        assert!(basic_credentials("Basic").is_none());
        assert!(basic_credentials("Digest dTpw").is_none());
    }

    #[test]
    fn separates_pipelined_connect_payload() {
        let request = b"CONNECT example.com:443 HTTP/1.1\r\n\r\nTLS";
        let end = find_header_end(request).unwrap();
        assert_eq!(&request[end..], b"TLS");
    }

    #[test]
    fn bare_line_terminators_are_rejected() {
        assert!(assert_strict_crlf(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n").is_ok());
        // A bare LF is the one that used to parse locally and differ upstream.
        assert!(assert_strict_crlf(b"GET http://a/\nHost: b\r\n\r\n").is_err());
        assert!(assert_strict_crlf(b"GET / HTTP/1.1\r\r\nHost: a").is_err());
        assert!(assert_strict_crlf(b"GET / HTTP/1.1\r\nHost: a\r\n\0").is_err());
    }

    #[test]
    fn rewrite_only_ever_touches_the_request_line() {
        // `handle()` rejects this block first, but the rewriter splices
        // `..end`, so on its own it must refuse rather than absorb a header.
        let evil = b"GET http://a/\nX-Injected: 1\r\nHost: a\r\n\r\n".to_vec();
        assert!(
            rewrite_absolute_uri(evil).is_err(),
            "a request line containing a bare LF must not be rewritten"
        );

        let ok = b"GET http://a/x?y=1 HTTP/1.1\r\nHost: a\r\n\r\n".to_vec();
        let out = rewrite_absolute_uri(ok).unwrap();
        assert!(out.starts_with(b"GET /x?y=1 HTTP/1.1\r\nHost: a"));
    }

    #[test]
    fn rewrite_absolute_uri_preserves_query_string() {
        // Path with query
        let req1 =
            b"GET http://example.com/api/test?foo=bar&baz=1 HTTP/1.1\r\nHost: example.com\r\n\r\n"
                .to_vec();
        let res1 = rewrite_absolute_uri(req1).unwrap();
        assert!(res1.starts_with(b"GET /api/test?foo=bar&baz=1 HTTP/1.1\r\n"));

        // Bare domain with query (no path slash before query)
        let req2 = b"GET http://example.com?foo=bar HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec();
        let res2 = rewrite_absolute_uri(req2).unwrap();
        assert!(res2.starts_with(b"GET /?foo=bar HTTP/1.1\r\n"));

        // Domain with port and query containing a slash (no path slash before query)
        let req3 = b"GET http://example.com:8080?filter=/root/dir HTTP/1.1\r\nHost: example.com:8080\r\n\r\n".to_vec();
        let res3 = rewrite_absolute_uri(req3).unwrap();
        assert!(res3.starts_with(b"GET /?filter=/root/dir HTTP/1.1\r\n"));

        // Bare domain without query or slash
        let req4 = b"GET http://example.com HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec();
        let res4 = rewrite_absolute_uri(req4).unwrap();
        assert!(res4.starts_with(b"GET / HTTP/1.1\r\n"));

        // Standard origin form is untouched
        let req5 = b"GET /already/origin?foo=1 HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec();
        let res5 = rewrite_absolute_uri(req5.clone()).unwrap();
        assert_eq!(res5, req5);
    }
}
