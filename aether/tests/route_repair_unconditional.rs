//! T033 — host-state repair must be callable unconditionally, at startup, without
//! ever entering TUN mode.
//!
//! Recovery used to hang off `tun_win::spawn`: a crashed run's split-default
//! routes were only reclaimed the next time somebody turned TUN on, so a GUI that
//! only ever uses the SOCKS/HTTP proxies left a black-holed routing table in place
//! indefinitely. The entry point is now `route_repair::repair_host_state_now` (and
//! its async twin), and the safety that lets it run at any moment is
//! `decide_replay`, tested below.

use aether::route_repair::{
    self, decide_replay, list_journal_paths, repair_host_state_now, Liveness, Replay, RouteJournal,
};

/// A stand-in for "this boot", as [`aether::route_repair::combine_liveness`]
/// understands it: any journal written more than its 300 s slack before this came
/// from an earlier boot, and no process survives a reboot.
const THIS_BOOT: u64 = 1_700_000_000;

fn journal(creator_pid: u32) -> RouteJournal {
    journal_written_in(creator_pid, THIS_BOOT)
}

fn journal_written_in(creator_pid: u32, created_unix: u64) -> RouteJournal {
    RouteJournal {
        version: route_repair::JOURNAL_VERSION,
        created_unix,
        creator_pid,
        tun_if_index: 44,
        phys_if_index: 11,
        gateway: "192.168.1.1".into(),
        tunnel_ipv4: "172.16.0.2".into(),
        peer_ipv4: "162.159.193.1".into(),
        ..RouteJournal::default()
    }
}

#[test]
fn replay_only_acts_on_a_journal_whose_holder_is_demostrably_gone() {
    let me = 9_999;
    assert_eq!(
        decide_replay(&journal(4242), Liveness::Dead, me, THIS_BOOT),
        Replay::Remove,
        "a crashed run's routes are the whole point of the replay"
    );
    for (holder, why) in [(Liveness::Alive, "alive"), (Liveness::Unknown, "unknown")] {
        assert!(
            matches!(
                decide_replay(&journal(4242), holder, me, THIS_BOOT),
                Replay::LeaveAlone(_)
            ),
            "a holder that is {why} must never have its routes deleted"
        );
    }
    // Our own journal, this boot: this is the call that fires inside
    // `tun_win::spawn`, and it must not delete the routes the caller is about to
    // install — even if a liveness probe were to answer oddly for our own pid.
    assert!(matches!(
        decide_replay(&journal(me), Liveness::Dead, me, THIS_BOOT),
        Replay::LeaveAlone(_)
    ));
    // Pid reuse across a reboot. The journal names *our* pid but was written in an
    // earlier boot, so it cannot be ours: no process survives a reboot, and the
    // caller has already reasoned that through `combine_liveness`. Deciding on pid
    // equality alone discarded that verdict, so such a journal was never replayed
    // and never deleted — its routes kept black-holing traffic indefinitely.
    assert_eq!(
        decide_replay(
            &journal_written_in(me, THIS_BOOT - 10_000),
            Liveness::Dead,
            me,
            THIS_BOOT
        ),
        Replay::Remove,
        "a recycled pid must not claim an earlier boot's journal"
    );
    // A journal from before the boot field existed carries no creation time, so
    // there is no evidence it is not ours; it stays conservative.
    assert!(matches!(
        decide_replay(&journal_written_in(me, 0), Liveness::Alive, me, THIS_BOOT),
        Replay::LeaveAlone(_)
    ));
    // No owner recorded at all is not evidence that nobody owns it.
    assert!(matches!(
        decide_replay(&journal(0), Liveness::Dead, me, THIS_BOOT),
        Replay::LeaveAlone(_)
    ));
}

#[test]
fn repair_can_be_called_twice_from_a_quiet_machine() {
    // The startup call must be safe to make before anything exists to repair, and
    // idempotent: a second call finds nothing left to do. Skipped rather than
    // failed if a real journal is present, because this test must not delete the
    // machine it runs on.
    let present = list_journal_paths();
    if !present.is_empty() {
        let count = present.len();
        eprintln!("skipping: {count} journal(s) already exist");
        return;
    }
    repair_host_state_now();
    repair_host_state_now();
    assert!(
        list_journal_paths().is_empty(),
        "a no-op repair must not create host state"
    );
}

#[test]
fn the_replay_effect_runs_only_for_journals_it_acted_on() {
    // The loop is pure I/O plus an injected effect, so the counting contract —
    // "how many journals did we actually tear down" — is checkable without a NIC.
    // Empty journal set on a CI box: zero effects, no panic.
    if !list_journal_paths().is_empty() {
        eprintln!("skipping: a real journal is present");
        return;
    }
    let counter = std::cell::Cell::new(0usize);
    let handled = route_repair::replay_abandoned_journals(
        |_pid| Liveness::Unknown,
        &|_journal: &RouteJournal| counter.set(counter.get() + 1),
    );
    assert_eq!(handled, 0);
    assert_eq!(
        counter.get(),
        0,
        "an unestablished holder never authorises a removal"
    );
}
