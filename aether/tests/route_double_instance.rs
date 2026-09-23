//! T036 — a second engine instance must refuse to mutate, not take over.
//!
//! There used to be one shared journal file. A second instance (the GUI's child
//! plus a hand-started `aether.exe`, or a scan child that also brings TUN up)
//! overwrote it, so the first process kept running against a record that no longer
//! described it — and whichever teardown ran last deleted prefixes the *other* one
//! had installed, on interfaces both of them share. The journal is now keyed per
//! owner (pid + boot id), and the newcomer's install path refuses.
//!
//! The refusal rule is a pure function over journal records, so "two owners, one
//! table" is checked here rather than on a machine with two NICs.

use aether::route_repair::{
    combine_liveness, decide_owner_exclusivity, journal_path_for, liveness_from_tasklist, owner_of,
    JournalOwner, Liveness, MutationVerdict, OwnershipRecord, RouteJournal,
};

const BOOT: u64 = 0x0000_1f00_2e00_0000;

fn owner(pid: u32, boot: u64) -> JournalOwner {
    JournalOwner {
        creator_pid: pid,
        boot_id: boot,
    }
}

fn record(pid: u32, boot: u64, tun_if: u32, holder: Liveness) -> OwnershipRecord {
    OwnershipRecord {
        owner: owner(pid, boot),
        tun_if_index: tun_if,
        holder,
    }
}

#[test]
fn a_second_live_instance_is_refused_rather_than_taking_over() {
    let first = record(111, BOOT, 44, Liveness::Alive);
    let verdict = decide_owner_exclusivity(&[first], &owner(222, BOOT), 44);
    match verdict {
        MutationVerdict::Refuse { why, owner: held } => {
            assert_eq!(held, owner(111, BOOT), "the refusal must name the holder");
            assert!(
                !why.is_empty(),
                "a refusal with no reason is not actionable in a log"
            );
        }
        MutationVerdict::Proceed => panic!("a second instance took over a live journal"),
    }
}

#[test]
fn an_unestablished_holder_is_treated_as_alive() {
    // `Unknown` is the direction that cannot damage a running session.
    let maybe = record(111, BOOT, 44, Liveness::Unknown);
    assert!(matches!(
        decide_owner_exclusivity(&[maybe], &owner(222, BOOT), 44),
        MutationVerdict::Refuse { .. }
    ));
}

#[test]
fn a_journal_whose_owner_is_on_a_different_interface_does_not_block_us() {
    // Disjoint tunnel NICs are disjoint routes; refusing here would make the
    // feature a permanent no-op on a multi-tunnel machine.
    let other = record(111, BOOT, 55, Liveness::Alive);
    assert_eq!(
        decide_owner_exclusivity(&[other], &owner(222, BOOT), 44),
        MutationVerdict::Proceed
    );
    // An interface index the other journal never recorded is *not* disjoint.
    let unattributed = record(111, BOOT, 0, Liveness::Alive);
    assert!(matches!(
        decide_owner_exclusivity(&[unattributed], &owner(222, BOOT), 44),
        MutationVerdict::Refuse { .. }
    ));
}

#[test]
fn a_dead_owners_journal_does_not_block_the_newcomer() {
    // The crashed run is what the replay is for; it must not wedge TUN forever.
    let stale = record(111, BOOT, 44, Liveness::Dead);
    assert_eq!(
        decide_owner_exclusivity(&[stale], &owner(222, BOOT), 44),
        MutationVerdict::Proceed
    );
    // And we may always rewrite our own journal mid-run: this is the second
    // install of the same process, which is normal.
    let ours = record(222, BOOT, 44, Liveness::Alive);
    assert_eq!(
        decide_owner_exclusivity(&[ours], &owner(222, BOOT), 44),
        MutationVerdict::Proceed
    );
    // No records at all.
    assert_eq!(
        decide_owner_exclusivity(&[], &owner(222, BOOT), 44),
        MutationVerdict::Proceed
    );
}

#[test]
fn two_owners_get_two_files_and_one_owner_gets_its_own_back() {
    let a = journal_path_for(&owner(111, BOOT)).expect("a state directory");
    let b = journal_path_for(&owner(222, BOOT)).expect("a state directory");
    let a_again = journal_path_for(&owner(111, BOOT)).expect("a state directory");
    assert_ne!(a, b, "two owners must not share one file");
    assert_eq!(a, a_again, "the same owner must land on the same file");
    assert_eq!(a.parent(), b.parent(), "both live in the journal directory");
    let name_a = a
        .file_name()
        .expect("a file name")
        .to_string_lossy()
        .into_owned();
    let name_b = b
        .file_name()
        .expect("a file name")
        .to_string_lossy()
        .into_owned();
    assert!(name_a.contains("111"), "{name_a} does not name its owner");
    assert!(name_b.contains("222"), "{name_b} does not name its owner");
    // A recycled pid in a later boot is a different file: the boot id is in it.
    let rebooted = journal_path_for(&owner(111, BOOT + 1)).expect("a state directory");
    assert_ne!(
        a, rebooted,
        "pid reuse must not inherit the previous boot's file"
    );
}

#[test]
fn a_journal_round_trips_its_owner_identity() {
    let journal = RouteJournal {
        creator_pid: 4242,
        boot_id: BOOT,
        tun_if_index: 44,
        ..RouteJournal::default()
    };
    let encoded = serde_json::to_string(&journal).expect("encode");
    let back: RouteJournal = serde_json::from_str(&encoded).expect("decode");
    assert_eq!(owner_of(&back), owner_of(&journal));
    assert_eq!(
        journal_path_for(&owner_of(&back)),
        journal_path_for(&owner_of(&journal))
    );
    // A file written before per-owner journals existed decodes to "unknown boot",
    // which is never equal to a real owner.
    let legacy: RouteJournal = serde_json::from_str(r#"{"version":1,"creator_pid":4242}"#)
        .expect("a legacy journal still parses");
    assert_eq!(legacy.boot_id, 0);
    assert_ne!(owner_of(&legacy), owner(4242, BOOT));
}

#[test]
fn a_recycled_pid_from_an_earlier_boot_is_dead_not_alive() {
    // The kernel probe cannot tell a reused pid from the original; the boot
    // arithmetic can, and that is the answer the ownership rule gets.
    let probe = liveness_from_tasklist_row(111);
    assert_eq!(probe, Liveness::Alive);
    assert_eq!(
        combine_liveness(BOOT - 10_000, BOOT, probe),
        Liveness::Dead,
        "written a previous boot: whoever answers to that pid now is not the holder"
    );
    assert_eq!(combine_liveness(BOOT - 10, BOOT, probe), Liveness::Alive);
}

/// A minimal canned `tasklist` row, so this file does not re-derive the CSV shape.
fn liveness_from_tasklist_row(pid: u32) -> Liveness {
    let text = format!("\"aether.exe\",\"{pid}\",\"Console\",\"1\",\"12,340 K\"\r\n");
    liveness_from_tasklist(&text, pid)
}
