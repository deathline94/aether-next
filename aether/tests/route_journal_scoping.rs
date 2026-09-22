//! T031 — route journal scoping.
//!
//! The shipped removal path built its PowerShell text inline, so a journal whose
//! interface keys were both zero — which is exactly what a `#[serde(default)]`
//! legacy or hand-edited file produces — emitted
//! `Get-NetRoute -DestinationPrefix '0.0.0.0/1' | Remove-NetRoute` with no
//! `Where-Object` at all. `0.0.0.0/1` + `128.0.0.0/1` is the prefix pair
//! OpenVPN/Cisco/AnyConnect use for split tunnelling, so an Aether disconnect
//! could take down an unrelated VPN.
//!
//! The renderer is now a pure function over one journal entry, so the property
//! that matters can be asserted without a NIC, an admin token, or a second VPN:
//! an unkeyed entry yields **no command**.

use aether::route_repair::{
    self, render_removal_command, PlannedRemoval, RouteIntent, RouteJournal, ScopeKind,
};

fn intent(destination: &str, mask: &str, next_hop: &str, if_index: u32) -> RouteIntent {
    RouteIntent {
        destination: destination.into(),
        mask: mask.into(),
        next_hop: next_hop.into(),
        if_index,
        family: 2,
    }
}

/// The exact shape a legacy `#[serde(default)]` file deserialises into: split
/// defaults, on-link, no interface keys, no tunnel address to fall back on.
fn unkeyed_journal() -> RouteJournal {
    RouteJournal {
        entries: vec![
            intent("0.0.0.0", "128.0.0.0", "0.0.0.0", 0),
            intent("128.0.0.0", "128.0.0.0", "0.0.0.0", 0),
        ],
        tun_if_index: 0,
        phys_if_index: 0,
        ..RouteJournal::default()
    }
}

#[test]
fn an_unkeyed_entry_renders_no_command_at_all() {
    let journal = unkeyed_journal();
    let plan = journal.removal_plan();
    assert!(!plan.is_empty(), "the journal is still read and judged");
    for entry in &plan {
        assert!(
            matches!(&entry.scope, ScopeKind::Refused { .. }),
            "unkeyed entry must be refused, got {:?}",
            entry.scope
        );
        assert!(
            render_removal_command(entry).is_none(),
            "an unkeyed entry must never produce removal text: {entry:?}"
        );
    }
    assert_eq!(journal.actionable_removals(), 0);
    let script = route_repair::powershell_script(&route_repair::removal_commands(&journal));
    assert!(
        !script.contains("Remove-NetRoute"),
        "a zero-keyed journal produced a deletion: {script}"
    );
}

#[test]
fn a_deserialised_legacy_file_produces_no_deletions() {
    // No `tun_if`, no `phys_if`, no `tunnel_ipv4`: everything defaults to zero or
    // empty, which is the input that used to reach the destructive branch.
    let journal: RouteJournal = serde_json::from_str(
        r#"{
            "version": 1,
            "entries": [
                {"destination": "0.0.0.0", "mask": "128.0.0.0", "next_hop": "0.0.0.0"},
                {"destination": "128.0.0.0", "mask": "128.0.0.0", "next_hop": "0.0.0.0"}
            ]
        }"#,
    )
    .expect("a legacy journal must still parse");
    assert_eq!(journal.tun_if_index, 0);
    assert_eq!(journal.phys_if_index, 0);
    assert!(
        journal
            .removal_plan()
            .iter()
            .all(|p| render_removal_command(p).is_none()),
        "a legacy file cannot authorise any deletion"
    );
}

#[test]
fn a_zero_interface_index_is_refused_by_the_renderer_itself() {
    // Defence in depth: even a caller that hands the renderer an `Interface`
    // scope with a zero index — bypassing `removal_plan` entirely — gets nothing.
    let entry = PlannedRemoval {
        destination: "0.0.0.0".into(),
        mask: "128.0.0.0".into(),
        scope: ScopeKind::Interface {
            if_index: 0,
            next_hop: Some("172.16.0.2".into()),
        },
    };
    assert!(render_removal_command(&entry).is_none());
}

#[test]
fn a_keyed_entry_is_scoped_to_interface_and_recorded_next_hop() {
    let journal = RouteJournal {
        creator_pid: 4242,
        tun_if_index: 44,
        phys_if_index: 11,
        gateway: "192.168.1.1".into(),
        tunnel_ipv4: "172.16.0.2".into(),
        peer_ipv4: "162.159.193.1".into(),
        entries: vec![
            intent("0.0.0.0", "128.0.0.0", "0.0.0.0", 44),
            intent("162.159.193.1", "255.255.255.255", "192.168.1.1", 11),
        ],
        ..RouteJournal::default()
    };
    let commands = route_repair::removal_commands(&journal);
    assert_eq!(commands.len(), 3, "2 entries + the peer escape");
    for command in &commands {
        // Never a bare `Remove-NetRoute`: the deletion is always piped through a
        // `Where-Object` that names something only our own route can match.
        assert!(
            command.contains("Where-Object"),
            "unscoped deletion rendered: {command}"
        );
        assert!(
            command.contains("Remove-NetRoute"),
            "the verb went missing: {command}"
        );
        assert!(
            command.contains("-InterfaceIndex"),
            "no interface scope: {command}"
        );
        assert!(
            command.contains(".NextHop -eq"),
            "no next-hop scope: {command}"
        );
    }
    assert!(commands[0].contains("'0.0.0.0/1'"));
    assert!(commands[0].contains("$_.InterfaceIndex -eq 44"));
    assert!(commands[0].contains("$_.NextHop -eq '0.0.0.0'"));
    assert!(commands[1].contains("$_.InterfaceIndex -eq 11"));
    assert!(commands[1].contains("$_.NextHop -eq '192.168.1.1'"));
    // The peer escape appears once from `entries` and once from the journal's own
    // peer field; both are equally scoped, and deleting twice is harmless.
    assert!(commands[2].contains("$_.InterfaceIndex -eq 11"));
}

#[test]
fn a_next_hop_only_removal_still_carries_a_filter() {
    // Interface identity unknown but our own tunnel address known: the filter has
    // to name that address, and nothing else may be matched.
    let journal = RouteJournal {
        tunnel_ipv4: "172.16.0.2".into(),
        entries: vec![intent("0.0.0.0", "128.0.0.0", "0.0.0.0", 0)],
        ..RouteJournal::default()
    };
    let commands = route_repair::removal_commands(&journal);
    assert_eq!(commands.len(), 1);
    assert!(commands[0].contains("$_.NextHop -eq '172.16.0.2'"));
    assert!(!commands[0].contains("-InterfaceIndex"));
}

#[test]
fn a_rejected_literal_never_reaches_the_script() {
    let smuggled = "0.0.0.0' | Remove-NetRoute -Force; '";
    let entry = PlannedRemoval {
        destination: "0.0.0.0".into(),
        mask: "128.0.0.0".into(),
        scope: ScopeKind::NextHop {
            next_hop: smuggled.into(),
        },
    };
    assert!(render_removal_command(&entry).is_none());
    let via_interface = PlannedRemoval {
        destination: "0.0.0.0".into(),
        mask: "128.0.0.0".into(),
        scope: ScopeKind::Interface {
            if_index: 44,
            next_hop: Some(smuggled.into()),
        },
    };
    assert!(render_removal_command(&via_interface).is_none());
}

#[test]
fn a_mask_that_is_not_a_netmask_is_refused_not_guessed() {
    let entry = PlannedRemoval {
        destination: "0.0.0.0".into(),
        mask: "255.0.255.0".into(),
        scope: ScopeKind::Interface {
            if_index: 44,
            next_hop: None,
        },
    };
    assert!(render_removal_command(&entry).is_none());
}
