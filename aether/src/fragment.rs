//! Shared TLS ClientHello TCP fragmentation with SNI-aware splitting.
//!
//! Splits the first outbound TLS flight (typically the ClientHello) across short
//! TCP segments with optional jittered inter-segment delays. When `sni_split` is
//! enabled and the first write parses as a TLS ClientHello with an SNI extension,
//! the very first segment cuts directly through the middle of the hostname so no
//! single TCP packet contains the complete SNI string.

use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use rand::Rng;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

#[derive(Debug, Clone, Copy)]
pub struct FragmentConfig {
    pub enabled: bool,
    pub size_min: usize,
    pub size_max: usize,
    pub delay_min_ms: u64,
    pub delay_max_ms: u64,
    pub sni_split: bool,
}

impl FragmentConfig {
    /// Legacy 1/3 split (no delay) when only `AETHER_H2_FRAG_CH=1` is set.
    pub fn legacy_on() -> Self {
        Self {
            enabled: true,
            size_min: 0,
            size_max: 0,
            delay_min_ms: 0,
            delay_max_ms: 0,
            sni_split: true,
        }
    }

    pub fn disabled() -> Self {
        Self {
            enabled: false,
            size_min: 0,
            size_max: 0,
            delay_min_ms: 0,
            delay_max_ms: 0,
            sni_split: false,
        }
    }

    /// Sensible SNI-splitting fallback preset for WARP API calls when unfragmented
    /// direct and edge attempts cannot complete TLS on DPI-filtered paths.
    pub fn sni_default() -> Self {
        Self {
            enabled: true,
            size_min: 16,
            size_max: 32,
            delay_min_ms: 2,
            delay_max_ms: 8,
            sni_split: true,
        }
    }

    /// Random-fragmentation mode driven by `AETHER_MASQUE_H2_FRAGMENT*` via `runtime_env`.
    pub fn from_env() -> Self {
        let enabled = match crate::runtime_env::var("AETHER_MASQUE_H2_FRAGMENT") {
            Some(v) => {
                !is_falsy(&v)
                    && (v.trim() == "1"
                        || v.trim().eq_ignore_ascii_case("true")
                        || v.trim().eq_ignore_ascii_case("on"))
            }
            None => false,
        };
        if !enabled {
            return Self::disabled();
        }
        let (size_min, size_max) = parse_range(
            &crate::runtime_env::var("AETHER_MASQUE_H2_FRAGMENT_SIZE").unwrap_or_default(),
            (16, 32),
        );
        let (delay_min_ms, delay_max_ms) = parse_range(
            &crate::runtime_env::var("AETHER_MASQUE_H2_FRAGMENT_DELAY").unwrap_or_default(),
            (2, 10),
        );
        let size_min = (size_min as usize).max(1);
        let size_max = (size_max.max(size_min as u64) as usize).max(1);
        let sni_split = crate::runtime_env::var("AETHER_MASQUE_H2_FRAGMENT_SNI")
            .map(|v| !is_falsy(&v) && crate::runtime_env::truthy(&v))
            .unwrap_or(true);
        Self {
            enabled: true,
            size_min,
            size_max,
            delay_min_ms,
            delay_max_ms: delay_max_ms.max(delay_min_ms),
            sni_split,
        }
    }

    pub fn pick_chunk_len(&self, remaining: usize) -> usize {
        if remaining <= 1 {
            return remaining;
        }
        if self.size_max == 0 {
            return (remaining / 3)
                .max(90)
                .min(remaining.saturating_sub(1))
                .max(1);
        }
        let mut rng = rand::thread_rng();
        let hi = self.size_max.min(remaining);
        let lo = self.size_min.min(hi).max(1);
        if lo >= hi {
            hi
        } else {
            rng.gen_range(lo..=hi)
        }
    }

    pub fn pick_delay(&self) -> Duration {
        if self.delay_max_ms == 0 {
            return Duration::ZERO;
        }
        let mut rng = rand::thread_rng();
        let ms = if self.delay_max_ms <= self.delay_min_ms {
            self.delay_min_ms
        } else {
            rng.gen_range(self.delay_min_ms..=self.delay_max_ms)
        };
        Duration::from_millis(ms)
    }
}

pub fn is_falsy(v: &str) -> bool {
    matches!(
        v.trim().to_ascii_lowercase().as_str(),
        "0" | "false" | "no" | "off"
    )
}

pub fn parse_range(spec: &str, default: (u64, u64)) -> (u64, u64) {
    let spec = spec.trim();
    if spec.is_empty() {
        return default;
    }
    match spec.split_once('-') {
        Some((a, b)) => {
            let lo = a.trim().parse().unwrap_or(default.0);
            let hi = b.trim().parse().unwrap_or(default.1);
            if hi < lo {
                (hi, lo)
            } else {
                (lo, hi)
            }
        }
        None => {
            let v = spec.parse().unwrap_or(default.0);
            (v, v)
        }
    }
}

/// Locate the byte range of the first SNI `host_name` inside a TLS ClientHello
/// record (`0x16` + Handshake ClientHello `0x01`) so the initial TCP write can
/// cleave directly through the domain string.
pub fn sni_host_range(buf: &[u8]) -> Option<(usize, usize)> {
    let take = |at: usize, n: usize| -> Option<usize> {
        let end = at.checked_add(n)?;
        let slice = buf.get(at..end)?;
        Some(slice.iter().fold(0usize, |acc, b| (acc << 8) | *b as usize))
    };

    if *buf.first()? != 0x16 || *buf.get(5)? != 0x01 {
        return None;
    }

    // TLS record header (5) + handshake header (4) + legacy_version (2) + random (32) = 43.
    let mut at = 43usize;
    at = at.checked_add(1)?.checked_add(take(at, 1)?)?;
    at = at.checked_add(2)?.checked_add(take(at, 2)?)?;
    at = at.checked_add(1)?.checked_add(take(at, 1)?)?;

    let ext_len = take(at, 2)?;
    at = at.checked_add(2)?;
    let extensions_end = at.checked_add(ext_len)?.min(buf.len());

    while at.checked_add(4)? <= extensions_end {
        let kind = take(at, 2)?;
        let len = take(at + 2, 2)?;
        let body = at.checked_add(4)?;
        let next = body.checked_add(len)?;
        if next > extensions_end {
            return None;
        }
        if kind == 0x0000 {
            let entry = body.checked_add(2)?;
            if take(entry, 1)? != 0 {
                return None;
            }
            let host_len = take(entry.checked_add(1)?, 2)?;
            let host = entry.checked_add(3)?;
            let host_end = host.checked_add(host_len)?;
            if host_len == 0 || host_end > next {
                return None;
            }
            return Some((host, host_end));
        }
        at = next;
    }

    None
}

pub struct FragmentingStream<S> {
    inner: S,
    cfg: FragmentConfig,
    fragmenting: bool,
    first_write: bool,
    pending_delay: Option<Pin<Box<tokio::time::Sleep>>>,
}

impl<S> FragmentingStream<S> {
    pub fn new(inner: S, cfg: FragmentConfig) -> Self {
        Self {
            inner,
            fragmenting: cfg.enabled,
            cfg,
            first_write: true,
            pending_delay: None,
        }
    }

    /// Stop fragmenting subsequent writes (called once the TLS handshake completes
    /// so post-handshake HTTP/H2 traffic writes at full throughput).
    pub fn stop_fragmenting(&mut self) {
        self.fragmenting = false;
        self.pending_delay = None;
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for FragmentingStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for FragmentingStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        if !this.fragmenting || !this.cfg.enabled || buf.len() < 16 {
            this.fragmenting = false;
            return Pin::new(&mut this.inner).poll_write(cx, buf);
        }

        if let Some(sleep) = this.pending_delay.as_mut() {
            if std::future::Future::poll(sleep.as_mut(), cx) != Poll::Ready(()) {
                return Poll::Pending;
            }
            this.pending_delay = None;
        }

        let targeted = if this.first_write && this.cfg.sni_split {
            sni_host_range(buf).map(|(start, end)| start + (end - start) / 2)
        } else {
            None
        };
        let chunk_len = match targeted {
            Some(split) if split > 0 && split < buf.len() => split,
            _ => this.cfg.pick_chunk_len(buf.len()),
        };

        // Once the remaining write fits below size_min (and not on the initial SNI
        // split itself so the rest of the ClientHello still gets chopped), mark done.
        let tail_is_tiny =
            !this.first_write && buf.len().saturating_sub(chunk_len) < this.cfg.size_min.max(1);
        if tail_is_tiny {
            this.fragmenting = false;
        }

        match Pin::new(&mut this.inner).poll_write(cx, &buf[..chunk_len]) {
            Poll::Ready(Ok(n)) => {
                if n > 0 {
                    this.first_write = false;
                    if this.fragmenting {
                        let delay = this.cfg.pick_delay();
                        if !delay.is_zero() {
                            this.pending_delay = Some(Box::pin(tokio::time::sleep(delay)));
                        }
                    }
                }
                Poll::Ready(Ok(n))
            }
            other => other,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    fn sample_client_hello(host: &str) -> Vec<u8> {
        let mut sni = vec![0x00];
        sni.extend_from_slice(&(host.len() as u16).to_be_bytes());
        sni.extend_from_slice(host.as_bytes());

        let mut list = (sni.len() as u16).to_be_bytes().to_vec();
        list.extend_from_slice(&sni);

        let mut ext = vec![0x00, 0x00];
        ext.extend_from_slice(&(list.len() as u16).to_be_bytes());
        ext.extend_from_slice(&list);

        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[0u8; 32]);
        body.push(0x00); // session_id len
        body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // cipher suites
        body.extend_from_slice(&[0x01, 0x00]); // compression
        body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        body.extend_from_slice(&ext);

        let mut handshake = vec![0x01];
        handshake.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        handshake.extend_from_slice(&body);

        let mut record = vec![0x16, 0x03, 0x01];
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    #[test]
    fn locates_sni_host_inside_client_hello() {
        let host = "api.cloudflareclient.com";
        let hello = sample_client_hello(host);
        let (start, end) = sni_host_range(&hello).expect("sni must be located");
        assert_eq!(&hello[start..end], host.as_bytes());
    }

    #[test]
    fn rejects_non_tls_and_truncated_client_hellos() {
        assert_eq!(sni_host_range(b"GET / HTTP/1.1\r\n"), None);
        let full = sample_client_hello("api.cloudflareclient.com");
        for cut in [0usize, 5, 43, full.len().saturating_sub(4)] {
            assert_eq!(sni_host_range(&full[..cut]), None);
        }
    }

    struct RecordingSink {
        writes: Vec<Vec<u8>>,
    }

    impl AsyncWrite for RecordingSink {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            self.writes.push(buf.to_vec());
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn first_write_splits_middle_of_sni_and_stop_passes_through() {
        let host = "api.cloudflareclient.com";
        let hello = sample_client_hello(host);
        let (s, e) = sni_host_range(&hello).unwrap();
        let expected_split = s + (e - s) / 2;

        let sink = RecordingSink { writes: Vec::new() };
        let cfg = FragmentConfig {
            enabled: true,
            size_min: 16,
            size_max: 16,
            delay_min_ms: 0,
            delay_max_ms: 0,
            sni_split: true,
        };
        let mut stream = FragmentingStream::new(sink, cfg);
        stream.write_all(&hello).await.unwrap();
        stream.stop_fragmenting();
        stream
            .write_all(b"POST /v0/reg HTTP/1.1\r\n")
            .await
            .unwrap();

        let sink = stream.inner;
        assert!(sink.writes.len() >= 3);
        assert_eq!(sink.writes[0].len(), expected_split);
        let rejoined_hello: Vec<u8> = sink.writes[..sink.writes.len() - 1]
            .iter()
            .flatten()
            .copied()
            .collect();
        assert_eq!(rejoined_hello, hello);
        assert_eq!(sink.writes.last().unwrap(), b"POST /v0/reg HTTP/1.1\r\n");
    }
}
