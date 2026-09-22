//! T137 / T149 — proxy traffic must not be able to take name resolution down.
//!
//! One shared 128-entry socket pool used to serve both client relays and the
//! engine's own DNS lookups. A browser that opened every UDP association (an
//! ordinary side effect of WebRTC or QUIC) therefore broke resolution, and with
//! resolution broken every domain `CONNECT` failed too — a client, not the
//! server, caused a total proxy outage.
//!
//! These run against a real in-process netstack through its public API. The
//! socket budget is what is under test, so no peer and no live network is
//! needed: admission happens before any packet goes out.

use std::net::SocketAddr;
use std::time::Duration;

use aether::netstack::{self, MAX_UDP_PROXY, MAX_UDP_RESOLVER};
use tokio::sync::mpsc;

/// A live netstack with no peer behind it: commands are served and sockets are
/// admitted, but nothing ever answers. The held sender keeps the ingress channel
/// open, which is what the stack's run loop waits on.
fn bare_stack() -> (netstack::StackHandle, mpsc::Sender<Vec<u8>>) {
    let (inbound_tx, inbound_rx) = mpsc::channel(64);
    let (outbound_tx, _outbound_rx) = mpsc::channel(64);
    let stack = netstack::spawn("10.0.0.2/24", "", 1500, inbound_rx, outbound_tx)
        .expect("the netstack spawns in-process, with no interface");
    (stack, inbound_tx)
}

/// Open UDP associations until the stack refuses, returning how many it granted
/// plus the senders that hold them (an association frees its slot on drop).
async fn exhaust_proxy_udp(stack: &netstack::StackHandle) -> Vec<netstack::UdpSender> {
    let mut held = Vec::new();
    loop {
        match tokio::time::timeout(Duration::from_secs(5), stack.open_udp()).await {
            Ok(Ok(conn)) => held.push(conn.into_split().0),
            Ok(Err(e)) => {
                let msg = e.to_string();
                assert!(
                    msg.contains("too many UDP associations"),
                    "the pool refused for a reason other than its budget: {msg}"
                );
                return held;
            }
            Err(_) => panic!("the netstack stopped answering open_udp: starvation, not a budget"),
        }
    }
}

#[tokio::test]
async fn proxy_association_exhaustion_leaves_dns_admissible() {
    let (stack, _inbound) = bare_stack();

    let held = exhaust_proxy_udp(&stack).await;
    assert_eq!(
        held.len(),
        MAX_UDP_PROXY,
        "the proxy UDP budget moved from the documented number"
    );

    // The whole point of the split: with every proxy association in use, the
    // resolver class still has all of its sockets.
    let mut resolver = Vec::new();
    for _ in 0..MAX_UDP_RESOLVER {
        match tokio::time::timeout(Duration::from_secs(5), stack.open_udp_resolver()).await {
            Ok(Ok(conn)) => resolver.push(conn.into_split().0),
            Ok(Err(e)) => panic!(
                "name resolution was starved by proxy traffic after {} proxy associations: {e}",
                held.len()
            ),
            Err(_) => panic!("the netstack stopped answering resolver opens"),
        }
    }
    // And only *then* is the resolver class full.
    let err = stack
        .open_udp_resolver()
        .await
        .err()
        .expect("the resolver class must be bounded too");
    assert!(
        err.to_string().contains("resolver"),
        "unexpected refusal: {err}"
    );

    assert!(stack.task_alive(), "the stack task exited under load");
}

#[tokio::test]
async fn dns_resolve_does_not_fail_on_a_proxy_budget_error() {
    let (stack, _inbound) = bare_stack();
    let held = exhaust_proxy_udp(&stack).await;
    assert!(!held.is_empty());

    // `dns_resolve` cannot complete without a peer, but it must fail *after*
    // getting its socket — a budget refusal here is the T137 outage.
    let err = tokio::time::timeout(Duration::from_secs(20), aether::socks::dns_resolve(&stack, "a.example"))
        .await
        .expect("resolution attempts, it does not hang")
        .expect_err("nothing answers inside `bare_stack`");
    let msg = err.to_string();
    assert!(
        !msg.contains("too many UDP associations (proxy)"),
        "DNS drew from the proxy budget and was starved by it: {msg}"
    );
    assert!(
        !msg.contains("too many UDP associations (resolver)"),
        "the resolver budget was already exhausted by proxy traffic: {msg}"
    );
    assert!(
        msg.contains("timeout") || msg.contains("record") || msg.contains("unexpected source"),
        "unexpected DNS failure mode: {msg}"
    );
}

/// A refused flow must be visible to its client *before* the budget: the
/// destination check is the one place a rebinding cannot walk around (T157).
#[tokio::test]
async fn metadata_and_loopback_targets_are_refused_at_the_choke_point() {
    let (stack, _inbound) = bare_stack();
    for dst in ["127.0.0.1:1337", "169.254.169.254:80", "100.64.0.1:53", "[::1]:443"] {
        let dst: SocketAddr = dst.parse().unwrap();
        let outcome = tokio::time::timeout(Duration::from_secs(5), stack.open_tcp(dst))
            .await
            .expect("the stack answers");
        let err = match outcome {
            Err(e) => e,
            Ok(_) => panic!("{dst} was admitted through the tunnel"),
        };
        let msg = err.to_string();
        assert!(
            msg.contains("not reachable through the tunnel"),
            "{dst} failed for the wrong reason: {msg}"
        );
    }
    assert!(stack.task_alive());
}

/// Closing an association returns its slot: a budget that is only ever
/// incremented is the same permanent outage as an unbounded one.
#[tokio::test]
async fn closed_associations_return_their_slot() {
    let (stack, _inbound) = bare_stack();
    let held = exhaust_proxy_udp(&stack).await;
    assert!(stack.open_udp().await.is_err(), "the pool was not full");

    for sender in held {
        sender.close().await;
    }
    let mut admitted = 0usize;
    for _ in 0..10 {
        if stack.open_udp().await.is_ok() {
            admitted += 1;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        admitted > 0,
        "closing every association never gave the proxy budget back"
    );
}
