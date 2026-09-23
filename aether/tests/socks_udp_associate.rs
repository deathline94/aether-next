//! T136 — the SOCKS5 UDP-associate origin table.
//!
//! The association is the one place where a *remote* source address is turned
//! into a datagram delivered to the local client, so the rules are load-bearing:
//! a reply may only go to the client that asked for it, an origin table that
//! fills up must age entries out rather than be wiped, and an association whose
//! client vanished must stop holding a socket.
//!
//! The map is per-association and the logic is pure, so this drives it with a
//! simulated clock instead of a live proxy: `Instant` arithmetic is the whole
//! difference between a passing and a failing assertion here.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use aether::socks::{
    association_expired, evict_origins, note_origin_at, origin_target, UDP_ASSOC_IDLE,
    UDP_ASSOC_TICK, UDP_ORIGIN_MAX, UDP_ORIGIN_TTL,
};

type Origins = HashMap<SocketAddr, (SocketAddr, Instant)>;

/// A peer address, unique per index, standing in for "a destination the client
/// sent to".
fn peer(i: usize) -> SocketAddr {
    SocketAddr::new(IpAddr::from([1, 2, (i / 251) as u8, (i % 251) as u8]), 443)
}

const CLIENT_A: SocketAddr =
    SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)), 5150);
const CLIENT_B: SocketAddr =
    SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)), 5151);

/// A destination the association never contacted must not be able to reach the
/// client — and specifically must not be forwarded to whoever happens to be
/// pinned, which is what the old `.or(client)` fallback did.
#[test]
fn unmapped_origin_is_dropped_rather_than_forwarded_to_the_pinned_client() {
    let base = Instant::now();
    let mut map: Origins = HashMap::new();
    note_origin_at(&mut map, peer(1), CLIENT_A, base);

    assert_eq!(
        origin_target(&mut map, peer(2), base + Duration::from_secs(1)),
        None,
        "a datagram from a destination this association never contacted was forwarded"
    );
    // Even with a client pinned and exactly one origin in the table, an unknown
    // source yields nothing to send to.
    assert_eq!(map.len(), 1, "a rejected lookup must not mutate the table");
}

/// Overflow used to be handled with `map.clear()`: one burst dropped every live
/// origin, so in-flight connections lost their permitted peer *and* the next
/// unsolicited source looked exactly as good as a real one.
#[test]
fn overflow_ages_out_lru_instead_of_wiping_the_table() {
    let base = Instant::now();
    let mut map: Origins = HashMap::new();
    // All inside the TTL, all distinct: nothing here is legitimately dead, so
    // only the budget itself can justify removing an entry.
    for i in 0..UDP_ORIGIN_MAX {
        note_origin_at(
            &mut map,
            peer(i),
            CLIENT_A,
            base + Duration::from_millis(i as u64),
        );
    }
    assert_eq!(map.len(), UDP_ORIGIN_MAX);

    let first_new = peer(UDP_ORIGIN_MAX);
    note_origin_at(
        &mut map,
        first_new,
        CLIENT_B,
        base + Duration::from_millis(UDP_ORIGIN_MAX as u64),
    );
    assert!(
        map.len() <= UDP_ORIGIN_MAX,
        "the table stayed over budget after eviction: {}",
        map.len()
    );
    assert!(
        map.len() > UDP_ORIGIN_MAX / 2,
        "overflow evicted the whole table instead of ageing entries out: {}",
        map.len()
    );
    assert!(
        map.contains_key(&first_new),
        "the just-contacted origin must never be the one dropped"
    );
    // What goes is the *oldest* — the newest live conversation is kept.
    assert!(
        map.contains_key(&peer(UDP_ORIGIN_MAX - 1)),
        "a recently used origin was evicted before a stale one"
    );
}

/// Entries past the TTL stop receiving replies and are removed on touch.
#[test]
fn aged_out_origin_stops_forwarding_and_is_removed() {
    let base = Instant::now();
    let mut map: Origins = HashMap::new();
    note_origin_at(&mut map, peer(1), CLIENT_A, base);

    let later = base + UDP_ORIGIN_TTL + Duration::from_millis(1);
    assert_eq!(origin_target(&mut map, peer(1), later), None);
    assert!(
        !map.contains_key(&peer(1)),
        "an expired origin was left in the table to be looked up again"
    );
    assert_eq!(
        origin_target(&mut map, peer(1), later),
        None,
        "the removed origin came back"
    );
}

/// A reply refreshes its origin, so a busy flow is not the one eviction removes.
#[test]
fn a_used_origin_outlives_an_idle_one() {
    let base = Instant::now();
    let mut map: Origins = HashMap::new();
    note_origin_at(&mut map, peer(1), CLIENT_A, base);
    note_origin_at(&mut map, peer(2), CLIENT_A, base);

    // Only peer(1) keeps receiving traffic: exactly one lookup, which is also
    // what refreshes it.
    let now = base + UDP_ORIGIN_TTL - Duration::from_secs(10);
    assert_eq!(origin_target(&mut map, peer(1), now), Some(CLIENT_A));

    // peer(2) has now been idle past the TTL; peer(1) was just refreshed.
    let later = now + Duration::from_secs(11);
    assert_eq!(origin_target(&mut map, peer(1), later), Some(CLIENT_A));
    assert_eq!(
        origin_target(&mut map, peer(2), later),
        None,
        "an origin the client stopped talking to kept a reply route open"
    );
}

/// Each association carries only its own origins: a datagram arriving on one
/// association's socket cannot be delivered to another association's client.
#[test]
fn two_associations_do_not_share_forwarding_state() {
    let base = Instant::now();
    let mut first: Origins = HashMap::new();
    let mut second: Origins = HashMap::new();
    note_origin_at(&mut first, peer(7), CLIENT_A, base);
    note_origin_at(&mut second, peer(8), CLIENT_B, base);

    assert_eq!(origin_target(&mut first, peer(7), base), Some(CLIENT_A));
    assert_eq!(
        origin_target(&mut first, peer(8), base),
        None,
        "association one forwarded a datagram belonging to association two"
    );
    assert_eq!(origin_target(&mut second, peer(8), base), Some(CLIENT_B));
    assert_eq!(origin_target(&mut second, peer(7), base), None);
}

#[test]
fn periodic_prune_reaps_expired_origins_without_traffic() {
    let base = Instant::now();
    let mut map: Origins = HashMap::new();
    for i in 0..10 {
        note_origin_at(&mut map, peer(i), CLIENT_A, base);
    }
    note_origin_at(&mut map, peer(100), CLIENT_A, base + UDP_ORIGIN_TTL);

    let removed = evict_origins(&mut map, base + UDP_ORIGIN_TTL + Duration::from_secs(1));
    assert_eq!(removed, 10, "prune reaped the live origin too");
    assert_eq!(map.len(), 1);
    assert!(map.contains_key(&peer(100)));
}

/// The reaper must bite before the session cap, and it must be checked more
/// often than the limit it enforces.
#[test]
fn idle_association_expires_and_the_tick_is_finer_than_the_limit() {
    let base = Instant::now();
    assert!(!association_expired(base, base));
    assert!(!association_expired(
        base,
        base + UDP_ASSOC_IDLE - Duration::from_millis(1)
    ));
    assert!(association_expired(base, base + UDP_ASSOC_IDLE));
    assert!(association_expired(base, base + UDP_ASSOC_IDLE * 2));
    assert!(UDP_ASSOC_TICK < UDP_ASSOC_IDLE);
    assert!(UDP_ASSOC_IDLE < Duration::from_secs(3600));
}
