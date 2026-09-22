//! T163 — the session caps have to be honest.
//!
//! Two limits were invisible from the client's side:
//!
//! * `MAX_CLIENTS` at saturation dropped the accepted socket without a single
//!   reply byte, which a client experiences as a refused/reset connection with
//!   no reason attached. It now gets a protocol-level refusal.
//! * `MAX_SESSION` aborted a four-hour session silently, mid-stream.
//!
//! The refusal is observable here because a live SOCKS listener is driven to its
//! limit over loopback against a real (if peerless) netstack.

use std::net::SocketAddr;
use std::time::Duration;

use aether::netstack;
use aether::socks::{self, MAX_CLIENTS, MAX_SESSION, SOCKS_GREETING_REFUSAL};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

const VER: u8 = 0x05;
const NO_AUTH: u8 = 0x00;

fn bare_stack() -> (netstack::StackHandle, mpsc::Sender<Vec<u8>>) {
    let (inbound_tx, inbound_rx) = mpsc::channel(64);
    let (outbound_tx, _outbound_rx) = mpsc::channel(64);
    let stack = netstack::spawn("10.0.0.2/24", "", 1500, inbound_rx, outbound_tx)
        .expect("the netstack spawns in-process");
    (stack, inbound_tx)
}

/// A client that is *admitted* gets a greeting reply naming a method; a client
/// that is refused gets the no-acceptable-methods code. Both are two bytes, so
/// the assertion on the bytes is the whole difference between the two paths —
/// which is exactly why "read two bytes and check them" is the test.
async fn greeting(sock: &mut TcpStream) -> [u8; 2] {
    sock.write_all(&[VER, 0x01, NO_AUTH]).await.expect("greeting");
    let mut reply = [0u8; 2];
    sock.read_exact(&mut reply).await.expect("greeting reply");
    reply
}

#[tokio::test]
async fn saturated_client_limit_answers_with_a_refusal_not_a_reset() {
    let (stack, _inbound) = bare_stack();
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr: SocketAddr = listener.local_addr().unwrap();
    let serve = tokio::spawn(async move { socks::serve_listener(listener, stack).await });

    // Hold the pool exactly full. Each of these completes its greeting and then
    // sits idle, which is what occupies a permit.
    let mut held = Vec::with_capacity(MAX_CLIENTS);
    for i in 0..MAX_CLIENTS {
        let mut sock = tokio::time::timeout(Duration::from_secs(10), TcpStream::connect(addr))
            .await
            .unwrap_or_else(|_| panic!("connect {i} timed out: the accept loop is blocked"))
            .expect("connect");
        let reply = tokio::time::timeout(Duration::from_secs(10), greeting(&mut sock))
            .await
            .expect("an admitted client is answered");
        assert_eq!(reply, [VER, NO_AUTH], "client {i} was not admitted normally");
        held.push(sock);
    }

    // The next client must be *told*, not reset.
    let mut extra = TcpStream::connect(addr).await.expect("connect");
    extra
        .write_all(&[VER, 0x01, NO_AUTH])
        .await
        .expect("greeting write");
    let mut refused = [0u8; 2];
    tokio::time::timeout(Duration::from_secs(10), extra.read_exact(&mut refused))
        .await
        .expect("the refusal arrived instead of the connection going quiet")
        .expect("read refusal");
    assert_eq!(
        refused, SOCKS_GREETING_REFUSAL,
        "an over-limit client must get the greeting-level refusal"
    );
    assert_eq!(refused, [VER, 0xff]);
    drop(extra);

    // Releasing a permit makes the next client admissible again.
    if let Some(freed) = held.pop() {
        drop(freed);
    }
    let mut again = TcpStream::connect(addr).await.expect("connect");
    let reply = tokio::time::timeout(Duration::from_secs(10), greeting(&mut again))
        .await
        .expect("a freed permit must admit the next client")
        .to_vec();
    assert_eq!(reply, vec![VER, NO_AUTH]);

    serve.abort();
}

/// The cap and its explanation are part of the product's contract, not a magic
/// number in a log the user never sees.
#[test]
fn session_limit_is_documented_in_the_message_it_emits() {
    let msg = socks::session_cap_message("socks", MAX_SESSION);
    assert!(msg.contains("maximum session length"), "{msg}");
    assert!(msg.contains("4h"), "the limit must be readable: {msg}");
    assert!(msg.contains("Reconnect"), "{msg}");
    assert!(
        MAX_SESSION >= Duration::from_secs(60 * 60),
        "a session cap below an hour would end ordinary browsing"
    );
}
