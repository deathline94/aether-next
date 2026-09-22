//! T035 — PID liveness must be an exact column match.
//!
//! The shipped check was `stdout.contains(&pid.to_string())` over the whole text
//! a process query printed. `tasklist` puts a working-set column (`12,340 K`), a
//! session name and a session number next to every pid, so journal pid `4` matched
//! rows that had nothing to do with pid 4: a long-dead holder looked alive, its
//! routes were never reclaimed, and the machine stayed black-holed through a route
//! owned by a process that no longer existed.
//!
//! The parsing is a pure function over canned output, asserted here. The impure
//! caller (`tun_win::process_liveness`) asks the kernel first and falls back to
//! exactly this text.

use aether::route_repair::{combine_liveness, liveness_from_tasklist, Liveness, RouteJournal};

/// `tasklist /FI "PID eq 472" /NH /FO CSV` — the shape the engine actually asks
/// for. Note the memory column: it is full of the digits a substring match eats.
const CSV_HIT: &str = "\"aether.exe\",\"472\",\"Console\",\"1\",\"1,234,567 K\"\r\n";

const CSV_MISS: &str = "\"Memory Compression\",\"40\",\"Services\",\"0\",\"89,120 K\"\r\n\
                         \"svchost.exe\",\"1724\",\"Services\",\"0\",\"12,340 K\"\r\n";

const TABLE_HIT: &str = "Image Name                     PID Session Name        Session#    Mem Usage\n\
========================= ======== ================ =========== ============\n\
aether.exe                    472 Console                    1      9,640 K\n";

const TABLE_MISS: &str = "Image Name                     PID Session Name        Session#    Mem Usage\n\
========================= ======== ================ =========== ============\n\
svchost.exe                   4720 Console                    1     12,340 K\n\
dwm.exe                       1472 Console                    1     98,760 K\n";

#[test]
fn an_exact_pid_column_match_is_alive() {
    assert_eq!(liveness_from_tasklist(CSV_HIT, 472), Liveness::Alive);
    assert_eq!(liveness_from_tasklist(TABLE_HIT, 472), Liveness::Alive);
}

#[test]
fn the_memory_and_session_columns_cannot_impersonate_a_pid() {
    // Each value below is a substring of the raw text of `CSV_MISS` — of the
    // session number, of `89,120 K`, of `12,340 K`, of the `1724` pid — which is
    // exactly what the shipped `stdout.contains(pid)` answered "alive" to. None of
    // them is the value of a PID column.
    for not_running in [4u32, 172, 89, 9120, 12, 340, 1, 0, 12_340, 17] {
        assert_eq!(
            liveness_from_tasklist(CSV_MISS, not_running),
            Liveness::Dead,
            "{not_running} appears in a non-pid column and must not count as alive"
        );
    }
    assert_eq!(liveness_from_tasklist(TABLE_MISS, 472), Liveness::Dead);
    // A prefix of a real pid is not that pid.
    assert_eq!(liveness_from_tasklist(TABLE_MISS, 4720), Liveness::Alive);
    assert_eq!(liveness_from_tasklist(TABLE_MISS, 147), Liveness::Dead);
}

#[test]
fn the_quoted_pid_field_survives_commas_elsewhere_in_the_row() {
    // A naive `split(',').nth(1)` shifts when an image name contains a comma; the
    // CSV reader counts quoted fields instead, so the pid stays in column 1.
    let row = "\"weird,name.exe\",\"5\",\"Console\",\"1\",\"1,234 K\"\r\n";
    assert_eq!(liveness_from_tasklist(row, 5), Liveness::Alive);
    assert_eq!(liveness_from_tasklist(row, 1_234), Liveness::Dead);
    assert_eq!(liveness_from_tasklist(row, 234), Liveness::Dead);
}

#[test]
fn tasklists_own_no_match_banner_means_dead() {
    let banner = "INFO: No tasks are running which match the specified criteria.\r\n";
    assert_eq!(liveness_from_tasklist(banner, 4), Liveness::Dead);
}

#[test]
fn output_that_is_not_a_process_table_is_unknown_not_dead() {
    // `Unknown` must never be read as permission to delete: an empty buffer, a
    // crash dump on stdout, or a column order this reader does not know are all
    // reasons to leave a live tunnel's routes alone.
    assert_eq!(liveness_from_tasklist("", 4), Liveness::Unknown);
    assert_eq!(liveness_from_tasklist("\n\n   \n", 4), Liveness::Unknown);
    assert_eq!(
        liveness_from_tasklist("ERROR: Invalid argument\r\n", 4),
        Liveness::Unknown
    );
    assert_eq!(
        liveness_from_tasklist("Image Name  PID  Session Name\r\n", 4),
        Liveness::Unknown,
        "a header row is not data"
    );
}

#[test]
fn an_unattributed_journal_is_never_abandoned() {
    let journal = RouteJournal {
        creator_pid: 0,
        ..RouteJournal::default()
    };
    assert!(!journal.is_abandoned(Liveness::Dead));
    assert!(!journal.is_abandoned(Liveness::Alive));
    assert!(!journal.is_abandoned(Liveness::Unknown));

    let journal = RouteJournal {
        creator_pid: 472,
        ..RouteJournal::default()
    };
    assert!(journal.is_abandoned(Liveness::Dead));
    assert!(!journal.is_abandoned(Liveness::Alive));
    assert!(
        !journal.is_abandoned(Liveness::Unknown),
        "an unanswered probe must not authorise a deletion"
    );
}

#[test]
fn a_record_from_an_earlier_boot_is_dead_without_asking_the_kernel() {
    // Pid reuse: the recycled pid answers "alive" and the boot arithmetic answers
    // "impossible", and only the impossible one is evidence about *this* record.
    let created_previous_boot = 1_000_000;
    let this_boot = 2_000_000;
    assert_eq!(
        combine_liveness(
            created_previous_boot,
            this_boot,
            liveness_from_tasklist(CSV_HIT, 472)
        ),
        Liveness::Dead
    );
    // Written during this boot: the probe is the only authority.
    assert_eq!(
        combine_liveness(1_999_900, this_boot, Liveness::Alive),
        Liveness::Alive
    );
    assert_eq!(
        combine_liveness(1_999_900, this_boot, Liveness::Unknown),
        Liveness::Unknown
    );
}

#[test]
fn clock_skew_cannot_turn_a_live_holder_into_a_dead_one() {
    // The wrong direction deletes routes a running tunnel is using, so a record
    // that merely *looks* pre-boot has to clear a five minute margin first.
    let this_boot = 2_000_000;
    assert_eq!(
        combine_liveness(this_boot - 60, this_boot, Liveness::Alive),
        Liveness::Alive
    );
    assert_eq!(
        combine_liveness(this_boot - 3600, this_boot, Liveness::Alive),
        Liveness::Dead
    );
    // `created_unix == 0` is "not recorded", not "the epoch".
    assert_eq!(combine_liveness(0, this_boot, Liveness::Alive), Liveness::Alive);
    assert_eq!(
        combine_liveness(0, this_boot, Liveness::Unknown),
        Liveness::Unknown
    );
}
