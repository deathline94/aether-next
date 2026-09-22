use std::net::SocketAddr;
use std::time::{Duration, Instant};

use boring::pkey::PKey;
use boring::ssl::{ConnectConfiguration, SslConnector, SslMethod, SslVersion};
use boring::x509::X509;
use bytes::Bytes;
use http::Method;
use rand::Rng;
use tokio::net::TcpStream;
use tokio::sync::mpsc;

use crate::consts;
use crate::error::{AetherError, Result};
use crate::masque::{self, Capsule, CapsuleParser};
use crate::quic::{AssignedAddr, Internals};

// OpenSSL wire format: length-prefixed protocol list.
const H2_ALPN: &[u8] = b"\x02h2";
const CHROME_GROUPS: &str = "X25519:P-256:P-384";

pub struct H2TunnelConfig {
    pub peer: SocketAddr,
    pub sni: String,
    pub authority: String,
    pub cert_pem: Vec<u8>,
    pub key_pem: Vec<u8>,
    /// Preferred IPv4 source for data-plane DNS probe (edge-assigned / identity).
    pub probe_src: Option<std::net::Ipv4Addr>,
}

pub fn enabled() -> bool {
    match crate::runtime_env::var("AETHER_MASQUE_HTTP2") {
        Some(v) => {
            let v = v.trim().to_lowercase();
            v == "1" || v == "true" || v == "h2" || v == "yes" || v == "on"
        }
        None => false,
    }
}

pub fn h2_peer(quic_peer: SocketAddr) -> SocketAddr {
    if let Some(v) = crate::runtime_env::var("AETHER_MASQUE_H2_PEER") {
        if let Ok(addr) = v.trim().parse::<SocketAddr>() {
            return addr;
        }
    }
    quic_peer
}

/// Effective TLS SNI for the ClientHello.
///
/// Defaults to the configured MASQUE SNI, but `AETHER_MASQUE_SNI` lets the user
/// front behind a benign name (e.g. `cloudflare.com`) on networks that block the
/// MASQUE SNI via SNI-based DPI. The HTTP/2 `:authority` still targets the real
/// MASQUE host, so Cloudflare routes the CONNECT-IP correctly (domain fronting).
fn handshake_sni(default_sni: &str) -> String {
    crate::runtime_env::var("AETHER_MASQUE_SNI")
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| default_sni.to_string())
}

fn build_tls(cfg: &H2TunnelConfig) -> Result<boring::ssl::ConnectConfiguration> {
    let mut builder =
        SslConnector::builder(SslMethod::tls()).map_err(|e| AetherError::Tls(e.to_string()))?;

    builder
        .set_min_proto_version(Some(SslVersion::TLS1_2))
        .map_err(|e| AetherError::Tls(e.to_string()))?;
    builder
        .set_max_proto_version(Some(SslVersion::TLS1_3))
        .map_err(|e| AetherError::Tls(e.to_string()))?;

    builder.set_grease_enabled(true);

    let groups = crate::runtime_env::var("AETHER_TLS_GROUPS");
    let groups = groups
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(CHROME_GROUPS);
    builder
        .set_curves_list(groups)
        .map_err(|e| AetherError::Tls(e.to_string()))?;

    builder
        .set_alpn_protos(H2_ALPN)
        .map_err(|e| AetherError::Tls(e.to_string()))?;

    let cert = X509::from_pem(&cfg.cert_pem).map_err(|e| AetherError::Tls(e.to_string()))?;
    let key =
        PKey::private_key_from_pem(&cfg.key_pem).map_err(|e| AetherError::Tls(e.to_string()))?;
    builder
        .set_certificate(&cert)
        .map_err(|e| AetherError::Tls(e.to_string()))?;
    builder
        .set_private_key(&key)
        .map_err(|e| AetherError::Tls(e.to_string()))?;

    // SPKI pinning, shared with the H3 path so the two transports cannot drift
    // apart again. Hostname verification is driven by the pin set rather than
    // switched off globally for the whole process: an SNI-fronted edge needs its
    // name check relaxed *for that host only* (see
    // packaging/trust/masque-pins.json), and the former ambient env switches
    // (`the former ambient TLS kill-switch` / `the former ambient TLS kill-switch`)
    // are gone — any local process that could set one could previously disable
    // authentication for the whole tunnel.
    let pin_host = consts::CONNECT_SNI;
    let pin_sets = crate::trust::masque_pin_sets();
    crate::tls::install_pin_verification(&mut builder, pin_sets, pin_host)?;
    let require_hostname = pin_sets
        .iter()
        .any(|s| s.host.eq_ignore_ascii_case(pin_host) && s.require_hostname);

    let connector = builder.build();
    let mut config = connector
        .configure()
        .map_err(|e| AetherError::Tls(e.to_string()))?;
    config.set_verify_hostname(require_hostname);
    config.set_use_server_name_indication(true);

    Ok(config)
}

// ─── ClientHello fragmentation ──────────────────────────────────────────────

/// TCP wrapper that splits the FIRST write (the TLS ClientHello from
/// tokio-boring) across multiple TCP segments with optional inter-segment
/// delays. This defeats DPI boxes that fingerprint JA3/JA4 from a single
/// segment by introducing randomness into segment sizes and timing.
///
/// Two env control surfaces (composable):
///   - AETHER_H2_FRAG_CH=1                  legacy on/off toggle (simple 1/3 split)
///   - AETHER_MASQUE_H2_FRAGMENT={1|true}   full random-fragmentation mode
///   - AETHER_MASQUE_H2_FRAGMENT_SIZE=lo-hi byte range per chunk (default 16-32)
///   - AETHER_MASQUE_H2_FRAGMENT_DELAY=lo-hi ms between chunks (default 2-10)
struct FragFirstWrite {
    inner: TcpStream,
    /// Once true, all further writes pass through unchanged (only the first
    /// ClientHello-sized write is split).
    done: bool,
    /// Resolved fragment config (active only for the first write).
    cfg: FragmentConfig,
    /// Instant at which the next chunk may be written; None when fragmentation
    /// is idle. Stored as a plain Instant (Unpin) instead of `Pin<Sleep>` so
    /// the struct stays `Unpin` — `tokio_boring::connect` + `h2::handshake`
    /// require the inner stream to be `Unpin`.
    next_chunk_at: Option<std::time::Instant>,
}

#[derive(Debug, Clone, Copy)]
struct FragmentConfig {
    enabled: bool,
    size_min: usize,
    size_max: usize,
    delay_min_ms: u64,
    delay_max_ms: u64,
}

impl FragmentConfig {
    /// Legacy 1/3 split (no delay) when only `AETHER_H2_FRAG_CH=1` is set.
    fn legacy_on() -> Self {
        Self {
            enabled: true,
            size_min: 0,
            size_max: 0,
            delay_min_ms: 0,
            delay_max_ms: 0,
        }
    }

    fn disabled() -> Self {
        Self {
            enabled: false,
            size_min: 0,
            size_max: 0,
            delay_min_ms: 0,
            delay_max_ms: 0,
        }
    }

    /// Full random-fragmentation mode driven by AETHER_MASQUE_H2_FRAGMENT* env vars.
    /// Defaults when unset: chunks 16-32 bytes, delay 2-10 ms.
    fn from_env() -> Self {
        let enabled =
            is_truthy(&crate::runtime_env::var("AETHER_MASQUE_H2_FRAGMENT").unwrap_or_default());
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
        let size_min = (size_min.max(1) as usize).max(1);
        let size_max = (size_max.max(size_min as u64) as usize).max(1);
        Self {
            enabled: true,
            size_min,
            size_max,
            delay_min_ms,
            delay_max_ms: delay_max_ms.max(delay_min_ms),
        }
    }

    fn pick_chunk_len(&self, remaining: usize) -> usize {
        if self.size_max == 0 {
            // Legacy mode: split at one-third of the first write.
            return (remaining / 3)
                .max(90)
                .min(remaining.saturating_sub(1))
                .max(1);
        }
        let mut rng = rand::thread_rng();
        let hi = self.size_max.min(remaining);
        let lo = self.size_min.min(hi);
        if lo >= hi {
            hi
        } else {
            rng.gen_range(lo..=hi)
        }
    }

    fn pick_delay(&self) -> std::time::Duration {
        if self.delay_max_ms == 0 {
            return std::time::Duration::ZERO;
        }
        let mut rng = rand::thread_rng();
        let ms = if self.delay_max_ms <= self.delay_min_ms {
            self.delay_min_ms
        } else {
            rng.gen_range(self.delay_min_ms..=self.delay_max_ms)
        };
        std::time::Duration::from_millis(ms)
    }
}

fn is_truthy(v: &str) -> bool {
    matches!(
        v.trim().to_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

fn parse_range(spec: &str, default: (u64, u64)) -> (u64, u64) {
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

impl tokio::io::AsyncRead for FragFirstWrite {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        std::pin::Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for FragFirstWrite {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        // After the first write, OR if fragmentation disabled, OR slice too
        // small to fragment: forward untouched.
        if this.done || !this.cfg.enabled || buf.len() < 16 {
            this.done = true;
            return std::pin::Pin::new(&mut this.inner).poll_write(cx, buf);
        }

        // If an inter-chunk delay is pending, wait until its deadline elapses.
        // Poll a throwaway tokio Sleep future scoped to THIS poll cycle only —
        // storing a `Pin<Sleep>` in the struct would make it `!Unpin` and break
        // tokio_boring::connect / h2::handshake (both require `Unpin`). The
        // deadline (an Unpin `Instant`) is what we persist.
        if let Some(deadline) = this.next_chunk_at {
            let now = std::time::Instant::now();
            if now < deadline {
                let mut sleep = Box::pin(tokio::time::sleep_until(tokio::time::Instant::from_std(
                    deadline,
                )));
                if std::future::Future::poll(sleep.as_mut(), cx) != std::task::Poll::Ready(()) {
                    return std::task::Poll::Pending;
                }
            }
            this.next_chunk_at = None;
        }

        // First write only — split one chunk, let caller re-poll the remainder.
        // Multi-chunk fragmentation emerges naturally: tokio-boring keeps
        // calling poll_write with the leftover bytes; each call sends one chunk.
        // We flip `done` only when the final chunk is about to be sent so the
        // pattern terminates deterministically.
        let chunk_len = this.cfg.pick_chunk_len(buf.len());
        // Once the remaining buffer fits in a single chunk, mark done after this
        // write so subsequent writes pass straight through (post-ClientHello).
        if buf.len() - chunk_len < this.cfg.size_min.max(1) {
            this.done = true;
        }
        match std::pin::Pin::new(&mut this.inner).poll_write(cx, &buf[..chunk_len]) {
            std::task::Poll::Ready(Ok(n)) => {
                if n > 0 {
                    let delay = this.cfg.pick_delay();
                    if !delay.is_zero() {
                        this.next_chunk_at = Some(std::time::Instant::now() + delay);
                    }
                }
                std::task::Poll::Ready(Ok(n))
            }
            other => other,
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        std::pin::Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        std::pin::Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

/// Connect TLS with optional ClientHello fragmentation.
async fn connect_tls(
    config: ConnectConfiguration,
    sni: &str,
    tcp: TcpStream,
) -> Result<tokio_boring::SslStream<FragFirstWrite>> {
    // ClientHello fragmentation is opt-in: it can break strict TLS servers and
    // middleboxes, so H2 stays standards-compliant by default. Two control paths:
    //
    //   legacy simple 1/3 split:  AETHER_H2_FRAG_CH=1        (default: off)
    //   full random-fragmentation:  AETHER_MASQUE_H2_FRAGMENT=1 plus optional
    //     AETHER_MASQUE_H2_FRAGMENT_SIZE=lo-hi  (bytes per chunk, default 16-32)
    //     AETHER_MASQUE_H2_FRAGMENT_DELAY=lo-hi (ms between chunks, default 2-10)
    //
    // Full random takes precedence over the legacy toggle if both are set.
    let mut cfg = FragmentConfig::from_env();
    if !cfg.enabled {
        let legacy = crate::runtime_env::var("AETHER_H2_FRAG_CH")
            .map(|v| {
                let v = v.trim();
                v == "1" || v.eq_ignore_ascii_case("on") || v.eq_ignore_ascii_case("true")
            })
            .unwrap_or(false);
        if legacy {
            cfg = FragmentConfig::legacy_on();
        }
    }

    let wrapper = FragFirstWrite {
        inner: tcp,
        done: !cfg.enabled,
        cfg,
        next_chunk_at: None,
    };

    tokio_boring::connect(config, sni, wrapper)
        .await
        .map_err(|e| AetherError::Tls(format!("h2 tls handshake: {e}")))
}

fn build_connect_request(cfg: &H2TunnelConfig) -> Result<http::Request<()>> {
    let authority = format!("{}:443", cfg.authority);
    let uri = format!("https://{}", authority);
    // #8: Add random-length padding header to defeat H2 frame-size analysis.
    // DPI that fingerprints CONNECT frames by their exact byte length will see
    // a different size every session.
    let pad_len = rand::Rng::gen_range(&mut rand::thread_rng(), 16..=96);
    let padding: String = (0..pad_len).map(|_| 'x').collect();
    http::Request::builder()
        .method(Method::CONNECT)
        .uri(uri)
        .header("cf-connect-proto", consts::CF_CONNECT_PROTOCOL)
        .header("pq-enabled", "false")
        .header("user-agent", "")
        .header("x-pad", padding)
        .body(())
        .map_err(|e| AetherError::Masque(format!("build request: {e}")))
}

pub async fn verify_h2(cfg: &H2TunnelConfig, timeout: Duration) -> Result<Duration> {
    let start = Instant::now();
    let attempt = async {
        let tls_config = build_tls(cfg)?;
        let tcp = TcpStream::connect(cfg.peer)
            .await
            .map_err(AetherError::Io)?;
        let _ = tcp.set_nodelay(true);
        let tls = connect_tls(tls_config, &handshake_sni(&cfg.sni), tcp).await?;
        let (h2, connection) = h2::client::handshake(tls)
            .await
            .map_err(|e| AetherError::Masque(format!("h2 handshake: {e}")))?;
        let driver = tokio::spawn(async move {
            let _ = connection.await;
        });
        let mut h2 = h2
            .ready()
            .await
            .map_err(|e| AetherError::Masque(format!("h2 ready: {e}")))?;
        let req = build_connect_request(cfg)?;
        let (resp_fut, _send_stream) = h2
            .send_request(req, false)
            .map_err(|e| AetherError::Masque(format!("send_request: {e}")))?;
        let response = resp_fut
            .await
            .map_err(|e| AetherError::Masque(format!("await response: {e}")))?;
        driver.abort();
        let status = response.status();
        if !status.is_success() {
            return Err(AetherError::Masque(format!(
                "h2 connect-ip status {}",
                status.as_u16()
            )));
        }
        Ok(())
    };

    match tokio::time::timeout(timeout, attempt).await {
        Ok(Ok(())) => Ok(start.elapsed()),
        Ok(Err(e)) => Err(e),
        Err(_) => Err(AetherError::Other("h2 verify timeout".into())),
    }
}

pub async fn run(
    cfg: H2TunnelConfig,
    internals: Internals,
    addr_tx: Option<mpsc::Sender<AssignedAddr>>,
    ready_tx: tokio::sync::oneshot::Sender<()>,
) -> Result<()> {
    let (mut outbound_rx, inbound_tx) = internals.into_parts();

    let tls_config = build_tls(&cfg)?;

    log::info!("[h2] connecting tcp to {}", cfg.peer);
    let tcp = TcpStream::connect(cfg.peer)
        .await
        .map_err(AetherError::Io)?;
    let _ = tcp.set_nodelay(true);

    let tls = connect_tls(tls_config, &handshake_sni(&cfg.sni), tcp).await?;
    log::info!(
        "[h2] tls established; alpn={}",
        String::from_utf8_lossy(tls.ssl().selected_alpn_protocol().unwrap_or(b""))
    );

    // Flow-control windows sized to unblock a single CONNECT-IP stream without
    // over-allocating per tunnel (S6 fix). Defaults are modest; AETHER_H2_WINDOW_MB
    // can raise the stream window up to a hard cap of 32 MiB for high-BDP links.
    let win_mb = crate::runtime_env::var("AETHER_H2_WINDOW_MB")
        .and_then(|v| v.trim().parse::<u32>().ok())
        .unwrap_or(4)
        .clamp(1, 32);
    let stream_window = win_mb * 1024 * 1024;
    let conn_window = stream_window.saturating_mul(2);
    let mut h2_builder = h2::client::Builder::new();
    h2_builder.initial_window_size(stream_window);
    h2_builder.initial_connection_window_size(conn_window);
    h2_builder.max_frame_size(256 * 1024);
    let (h2, connection) = h2_builder
        .handshake(tls)
        .await
        .map_err(|e| AetherError::Masque(format!("h2 handshake: {e}")))?;
    tokio::spawn(async move {
        if let Err(e) = connection.await {
            log::debug!("[h2] connection driver ended: {e}");
        }
    });

    let mut h2 = h2
        .ready()
        .await
        .map_err(|e| AetherError::Masque(format!("h2 ready: {e}")))?;

    let req = build_connect_request(&cfg)?;

    let (resp_fut, mut send_stream) = h2
        .send_request(req, false)
        .map_err(|e| AetherError::Masque(format!("send_request: {e}")))?;
    log::info!("[h2] connect-ip request sent to {}", cfg.authority);

    let response = resp_fut
        .await
        .map_err(|e| AetherError::Masque(format!("await response: {e}")))?;
    let status = response.status();
    log::info!("[h2] connect-ip status: {}", status.as_u16());
    if !status.is_success() {
        return Err(AetherError::Masque(format!(
            "h2 connect-ip status {}",
            status.as_u16()
        )));
    }

    let mut recv_body = response.into_body();
    let mut capsules = CapsuleParser::new();

    // Prove data plane before advertising readiness (CONNECT 200 alone is insufficient).
    let probe_src = cfg
        .probe_src
        .unwrap_or_else(|| std::net::Ipv4Addr::new(198, 18, 0, 1));
    verify_dataplane(&mut send_stream, &mut recv_body, &mut capsules, probe_src).await?;
    log::info!("AETHER_EVENT {{\"type\":\"tunnel_ready\",\"transport\":\"h2\"}}");
    let _ = ready_tx.send(());

    // H3 fix: one shared "last traffic" stamp let a dead receive side be kept
    // alive forever by the sender's own keepalives (zombie half-tunnel: proxies
    // up, UI connected, all traffic black-holed). The stall detector now keys
    // exclusively on RECEIVE activity — inbound data is the only proof the path
    // actually works; successful sends alone prove nothing.
    let last_recv = std::sync::Arc::new(tokio::sync::Mutex::new(Instant::now()));
    let last_recv_send_watchdog = last_recv.clone();
    let probe_src_ka = probe_src;

    // CRITICAL: send and recv must not share one select. Waiting on H2 send capacity
    // used to block DATA recv + window updates → download collapsed under load.
    let send_task = tokio::spawn(async move {
        let mut last_send = Instant::now();
        let mut idle = tokio::time::interval(Duration::from_secs(20));
        idle.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = idle.tick() => {
                    // Zombie detection: if nothing has arrived for 90s the edge
                    // side is gone regardless of how fresh our own sends are.
                    let since_recv = last_recv_send_watchdog.lock().await.elapsed();
                    if since_recv > Duration::from_secs(90) {
                        return Err(AetherError::Masque(
                            "h2 stall: no data from edge for 90s".into(),
                        ));
                    }
                    // Keep-alive: small DNS probe so half-open links fail fast.
                    if last_send.elapsed() > Duration::from_secs(25) {
                        let probe = crate::dns::build_dataplane_probe(probe_src_ka, std::net::Ipv4Addr::new(8, 8, 8, 8));
                        if let Err(e) = send_ip_batch(&mut send_stream, vec![probe]).await {
                            log::debug!("[h2] keepalive: {e}");
                            return Err(e);
                        }
                        last_send = Instant::now();
                    }
                }
                pkt = outbound_rx.recv() => {
                    match pkt {
                        Some(ip_packet) => {
                            last_send = Instant::now();
                            let mut batch = Vec::with_capacity(64);
                            batch.push(ip_packet);
                            while batch.len() < 128 {
                                match outbound_rx.try_recv() {
                                    Ok(p) => batch.push(p),
                                    Err(_) => break,
                                }
                            }
                            if let Err(e) = send_ip_batch(&mut send_stream, batch).await {
                                log::debug!("[h2] send: {e}");
                                return Err(e);
                            }
                        }
                        None => {
                            let _ = send_stream.send_data(Bytes::new(), true);
                            return Ok(());
                        }
                    }
                }
            }
        }
    });

    let recv_task = tokio::spawn(async move {
        loop {
            match tokio::time::timeout(
                Duration::from_secs(45),
                futures::future::poll_fn(|cx| recv_body.poll_data(cx)),
            )
            .await
            {
                Ok(Some(Ok(chunk))) => {
                    *last_recv.lock().await = Instant::now();
                    let _ = recv_body.flow_control().release_capacity(chunk.len());
                    capsules.push(&chunk);
                    drain_capsules(&mut capsules, &inbound_tx, &addr_tx).await;
                }
                Ok(Some(Err(e))) => {
                    log::warn!("[h2] recv body error: {e}");
                    return Err(AetherError::Masque(format!("h2 body: {e}")));
                }
                Ok(None) => {
                    log::info!("[h2] server closed stream");
                    return Ok::<(), AetherError>(());
                }
                Err(_) => {
                    let since_recv = last_recv.lock().await.elapsed();
                    if since_recv > Duration::from_secs(90) {
                        return Err(AetherError::Masque(
                            "h2 stall: no data from edge for 90s".into(),
                        ));
                    }
                }
            }
        }
    });

    // Hold the handles by reference so they survive the select, then abort both:
    // whichever task ends first must take its sibling down with it instead of
    // leaving a detached half-tunnel behind.
    let mut send_task = send_task;
    let mut recv_task = recv_task;
    let result = tokio::select! {
        r = &mut send_task => {
            match r {
                Ok(Ok(())) => Ok(()),
                Ok(Err(e)) => Err(e),
                Err(e) => Err(AetherError::Masque(format!("h2 send task: {e}"))),
            }
        }
        r = &mut recv_task => {
            match r {
                Ok(Ok(())) => Ok(()),
                Ok(Err(e)) => Err(e),
                Err(e) => Err(AetherError::Masque(format!("h2 recv task: {e}"))),
            }
        }
    };
    send_task.abort();
    recv_task.abort();
    result
}

async fn verify_dataplane(
    send: &mut h2::SendStream<Bytes>,
    recv_body: &mut h2::RecvStream,
    capsules: &mut CapsuleParser,
    mut probe_src: std::net::Ipv4Addr,
) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(8);
    // The probe and the acceptance test have to name the same resolver, so both
    // come from the one knob (`AETHER_DATAPLANE_PROBE_IP`) the H3 path uses.
    let resolver = crate::dns::dataplane_probe_target();
    let mut resend_at = Instant::now();
    while Instant::now() < deadline {
        if Instant::now() >= resend_at {
            let probe = crate::dns::build_dataplane_probe(probe_src, resolver);
            send_ip_batch(send, vec![probe]).await?;
            resend_at = Instant::now() + Duration::from_millis(700);
        }
        let wait = deadline
            .saturating_duration_since(Instant::now())
            .min(Duration::from_millis(400));
        match tokio::time::timeout(wait, futures::future::poll_fn(|cx| recv_body.poll_data(cx)))
            .await
        {
            Ok(Some(Ok(chunk))) => {
                let _ = recv_body.flow_control().release_capacity(chunk.len());
                capsules.push(&chunk);
                loop {
                    match capsules.next() {
                        Ok(Some(Capsule::Datagram(pkt))) => {
                            // Readiness used to be "any datagram at all", so an
                            // edge that echoed our own probe back — or answered
                            // CONNECT-IP and then black-holed everything — marked
                            // the tunnel ready and got promoted into the trust
                            // cache. The predicate is the one the H2 tests already
                            // exercised with no production caller.
                            if crate::dns::is_dns_reply(&pkt, resolver) {
                                confirms += 1;
                                log::info!("[h2] data-plane verified (DNS reply from {resolver})");
                                return Ok(());
                            }
                            log::debug!(
                                "[h2] ignoring {}-byte datagram that is not a DNS reply from {resolver}",
                                pkt.len()
                            );
                        }
                        Ok(Some(Capsule::AddressAssign(addrs))) => {
                            for a in addrs {
                                if a.ip_version == 4 && a.address.len() == 4 {
                                    let new_ip = std::net::Ipv4Addr::new(
                                        a.address[0],
                                        a.address[1],
                                        a.address[2],
                                        a.address[3],
                                    );
                                    if new_ip != probe_src {
                                        log::info!(
                                            "[h2] edge assigned ipv4 {}, updating probe_src",
                                            new_ip
                                        );
                                        probe_src = new_ip;
                                        resend_at = Instant::now();
                                    }
                                }
                            }
                        }
                        Ok(Some(_)) => {}
                        Ok(None) => break,
                        Err(_) => break,
                    }
                }
            }
            Ok(Some(Err(e))) => {
                return Err(AetherError::Masque(format!("h2 verify recv: {e}")));
            }
            Ok(None) => {
                return Err(AetherError::Masque(
                    "h2 closed during data-plane verify".into(),
                ));
            }
            Err(_) => {}
        }
    }
    Err(AetherError::Masque(
        "h2 data-plane verify timeout (CONNECT ok, no traffic)".into(),
    ))
}

async fn send_capsule(send: &mut h2::SendStream<Bytes>, mut data: Bytes) -> Result<()> {
    if data.is_empty() {
        return Ok(());
    }

    // Send in whatever capacity the stream grants — waiting for full `len` stalls the
    // whole tunnel under load (single-stream CONNECT-IP carries every IP packet).
    while !data.is_empty() {
        let want = data.len();
        send.reserve_capacity(want);
        let n = match futures::future::poll_fn(|cx| send.poll_capacity(cx)).await {
            Some(Ok(n)) if n > 0 => n.min(want),
            Some(Ok(_)) => {
                send.reserve_capacity(want);
                continue;
            }
            Some(Err(e)) => return Err(AetherError::Masque(format!("h2 capacity: {e}"))),
            None => return Err(AetherError::Masque("h2 stream closed".into())),
        };
        let chunk = data.split_to(n);
        send.send_data(chunk, false)
            .map_err(|e| AetherError::Masque(format!("h2 send_data: {e}")))?;
    }
    Ok(())
}

/// Coalesce many IP packets into one or few H2 DATA frames.
async fn send_ip_batch(send: &mut h2::SendStream<Bytes>, packets: Vec<Vec<u8>>) -> Result<()> {
    if packets.is_empty() {
        return Ok(());
    }
    // Target ~32KB frames to cut H2 framing overhead without huge latency.
    const TARGET: usize = 32 * 1024;
    let mut buf = Vec::with_capacity(TARGET);
    for pkt in packets {
        let framed = masque::encode_datagram_capsule(&pkt);
        if !buf.is_empty() && buf.len() + framed.len() > TARGET {
            send_capsule(send, Bytes::from(std::mem::take(&mut buf))).await?;
            buf.reserve(TARGET);
        }
        buf.extend_from_slice(&framed);
    }
    if !buf.is_empty() {
        send_capsule(send, Bytes::from(buf)).await?;
    }
    Ok(())
}

async fn drain_capsules(
    capsules: &mut CapsuleParser,
    inbound_tx: &mpsc::Sender<Vec<u8>>,
    addr_tx: &Option<mpsc::Sender<AssignedAddr>>,
) {
    loop {
        match capsules.next() {
            Ok(Some(Capsule::Datagram(pkt))) => {
                // Prefer try_send so H2 recv keeps releasing windows. Fall back to await.
                match inbound_tx.try_send(pkt) {
                    Ok(()) => {}
                    Err(tokio::sync::mpsc::error::TrySendError::Full(pkt)) => {
                        if inbound_tx.send(pkt).await.is_err() {
                            return;
                        }
                    }
                    Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => return,
                }
            }
            Ok(Some(Capsule::AddressAssign(addrs))) => {
                for a in addrs {
                    if let Some(ip) = crate::tunnel::bytes_to_ip(a.ip_version, &a.address) {
                        log::info!("[h2] edge assigned {}/{}", ip, a.prefix_len);
                        if let Some(tx) = addr_tx {
                            let _ = tx.try_send(AssignedAddr {
                                ip,
                                prefix: a.prefix_len,
                            });
                        }
                    }
                }
            }
            Ok(Some(Capsule::RouteAdvertisement(routes))) => {
                for r in &routes {
                    log::info!(
                        "[h2] route advertisement: v{} proto {} {:?}-{:?}",
                        r.ip_version,
                        r.protocol,
                        r.start,
                        r.end
                    );
                }
            }
            Ok(Some(_)) => {}
            Ok(None) => break,
            Err(e) => {
                log::debug!("[h2] capsule parse: {e}");
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns;
    use crate::masque::CapsuleParser;

    fn probe(src: std::net::Ipv4Addr) -> Vec<u8> {
        dns::build_dataplane_probe(src, std::net::Ipv4Addr::new(8, 8, 8, 8))
    }

    #[test]
    fn dns_probe_is_ipv4_udp_to_1111() {
        let src = std::net::Ipv4Addr::new(198, 18, 0, 1);
        let pkt = probe(src);
        assert!(pkt.len() >= 28, "header+udp min");
        assert_eq!(pkt[0] >> 4, 4, "IPv4");
        assert_eq!(pkt[9], 17, "UDP");
        assert_eq!(&pkt[12..16], &src.octets());
        assert_eq!(&pkt[16..20], &[8, 8, 8, 8]);
        assert_eq!(u16::from_be_bytes([pkt[22], pkt[23]]), 53);
    }

    #[test]
    fn ipv4_checksum_field_zeroed_in_sum() {
        let pkt = probe(std::net::Ipv4Addr::new(10, 0, 0, 2));
        // Recompute: with stored checksum, ones-complement sum of header should be 0xffff.
        let mut sum = 0u32;
        for i in (0..20).step_by(2) {
            sum += u16::from_be_bytes([pkt[i], pkt[i + 1]]) as u32;
        }
        while sum > 0xffff {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        assert_eq!(sum as u16, 0xffff);
    }

    #[test]
    fn dataplane_accepts_only_dns_reply_from_resolver() {
        let resolver = std::net::Ipv4Addr::new(8, 8, 8, 8);
        // Outbound probe is a query (src != 1.1.1.1) and must NOT count as a reply.
        let p = probe(std::net::Ipv4Addr::new(198, 18, 0, 1));
        assert!(!dns::is_dns_reply(&p, resolver));

        // A real answer: from the resolver, source port 53, DNS flags with QR set.
        let mut reply = vec![0u8; 32];
        reply[0] = 0x45; // IPv4, IHL=5
        reply[9] = 17; // UDP
        reply[12..16].copy_from_slice(&[8, 8, 8, 8]); // src = 8.8.8.8
        reply[20..22].copy_from_slice(&53u16.to_be_bytes()); // src port 53
        reply[24] = 0x81; // flags: QR + RD
        assert!(dns::is_dns_reply(&reply, resolver));
    }

    /// The predicate behind the CONNECT-IP(H2) readiness gate.
    ///
    /// `verify_dataplane` used to accept *any* datagram, so an edge that echoed
    /// our own probe back — the cheapest possible fake — marked the tunnel ready,
    /// and the endpoint was credited and cached as working.
    #[test]
    fn an_echoed_probe_is_not_data_plane_proof() {
        let resolver = std::net::Ipv4Addr::new(8, 8, 8, 8);
        let echo = probe(std::net::Ipv4Addr::new(198, 18, 0, 1));
        assert!(
            !dns::is_dns_reply(&echo, resolver),
            "echo accepted as a reply"
        );

        // The same packet with the source address and port rewritten to look like
        // the resolver's: still a query (QR clear), still not proof.
        let mut spoof = echo.clone();
        spoof[12..16].copy_from_slice(&resolver.octets());
        spoof[20..22].copy_from_slice(&53u16.to_be_bytes());
        assert!(
            !dns::is_dns_reply(&spoof, resolver),
            "spoofed echo accepted"
        );

        // And a genuine reply must pass, or the gate would fail closed.
        let mut real = spoof.clone();
        real[24] |= 0x80;
        assert!(dns::is_dns_reply(&real, resolver), "real reply rejected");
    }

    #[test]
    fn datagram_capsule_roundtrip_for_probe() {
        let pkt = probe(std::net::Ipv4Addr::new(198, 18, 0, 1));
        let framed = masque::encode_datagram_capsule(&pkt);
        let mut parser = CapsuleParser::new();
        parser.push(&framed);
        match parser.next().expect("parse") {
            Some(Capsule::Datagram(got)) => assert_eq!(got, pkt),
            other => panic!("expected datagram, got {other:?}"),
        }
    }
}
