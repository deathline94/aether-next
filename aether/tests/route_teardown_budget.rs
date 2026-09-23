//! T032 — the teardown has to fit inside the supervisor's grace window, and
//! T044 — the route lifetime is a backstop, armed and re-armed.
//!
//! A cold `powershell.exe` start is 1-2 s on a loaded machine. The teardown used
//! to need three of them (route removal, adapter reset, and the proxy reset the
//! shell used to shell out for) plus `route.exe`, inside a 5 s window — so the
//! last one never ran and the host kept a dead tunnel's DNS and metric. The
//! whole teardown is now rendered as one command list for one process.

use std::time::Duration;

use aether::route_repair::{
    self, adapter_reset_commands, lifetime_refresh_commands, powershell_script, teardown_commands,
    teardown_plan, RouteIntent, RouteJournal,
};

const ADAPTER: &str = "Aether";

fn journal() -> RouteJournal {
    RouteJournal {
        version: route_repair::JOURNAL_VERSION,
        created_unix: 1,
        creator_pid: 4242,
        tun_alias: ADAPTER.into(),
        tun_if_index: 44,
        phys_if_index: 11,
        gateway: "192.168.1.1".into(),
        tunnel_ipv4: "172.16.0.2".into(),
        peer_ipv4: "162.159.193.1".into(),
        entries: vec![
            RouteIntent {
                destination: "0.0.0.0".into(),
                mask: "128.0.0.0".into(),
                next_hop: "0.0.0.0".into(),
                if_index: 44,
                family: 2,
            },
            RouteIntent {
                destination: "128.0.0.0".into(),
                mask: "128.0.0.0".into(),
                next_hop: "0.0.0.0".into(),
                if_index: 44,
                family: 2,
            },
            RouteIntent {
                destination: "162.159.193.1".into(),
                mask: "255.255.255.255".into(),
                next_hop: "192.168.1.1".into(),
                if_index: 11,
                family: 2,
            },
        ],
        ..RouteJournal::default()
    }
}

#[test]
fn the_whole_teardown_is_one_command_list_for_one_process() {
    let plan = teardown_plan(&journal(), ADAPTER);
    assert_eq!(plan.removals, 4, "3 entries + peer escape");
    assert_eq!(plan.refused, 0);
    let joined = plan.commands.join("\n");
    // Route deletions and the adapter reset travel together: a second spawn is a
    // second cold start, and that is what used to blow the window.
    assert!(joined.contains("Remove-NetRoute"));
    assert!(joined.contains("Set-DnsClientServerAddress"));
    assert!(joined.contains("Set-NetIPInterface"));
    assert!(joined.contains("-AutomaticMetric Enabled"));
    assert!(joined.contains("-ResetServerAddresses"));

    let script = powershell_script(&plan.commands);
    assert_eq!(
        script.matches("$ErrorActionPreference").count(),
        1,
        "one preamble means one powershell.exe; the script was {script}"
    );
    // Nothing here reaches for `route.exe`/`netsh`: those were the extra spawns.
    assert!(!script.contains("route delete"), "{script}");
    assert!(!script.contains("netsh"), "{script}");
    assert_eq!(
        script
            .lines()
            .filter(|l| l.contains("Remove-NetRoute"))
            .count(),
        plan.removals
    );
}

#[test]
fn teardown_commands_and_teardown_plan_agree() {
    let journal = journal();
    assert_eq!(
        teardown_commands(&journal, ADAPTER),
        teardown_plan(&journal, ADAPTER).commands
    );
}

#[test]
fn an_unkeyed_journal_resets_the_adapter_but_deletes_nothing() {
    let unkeyed = RouteJournal {
        entries: vec![RouteIntent {
            destination: "0.0.0.0".into(),
            mask: "128.0.0.0".into(),
            next_hop: "0.0.0.0".into(),
            if_index: 0,
            family: 2,
        }],
        ..RouteJournal::default()
    };
    let plan = teardown_plan(&unkeyed, ADAPTER);
    assert_eq!(plan.removals, 0);
    assert!(!plan.commands.iter().any(|c| c.contains("Remove-NetRoute")));
    // The adapter cleanup is *not* journal-scoped, so it still runs: a lingering
    // NIC with a dead tunnel's resolver is a host fault in its own right.
    assert_eq!(plan.commands, adapter_reset_commands(ADAPTER));
}

#[test]
fn an_unsafe_adapter_alias_renders_no_reset_but_still_removes_our_routes() {
    let hostile = "Aether'; Set-DnsClientServerAddress -InterfaceAlias 'evil";
    assert!(adapter_reset_commands(hostile).is_empty());
    let plan = teardown_plan(&journal(), hostile);
    assert_eq!(
        plan.removals, 4,
        "route scoping does not depend on the alias"
    );
    assert!(!plan.commands.iter().any(|c| c.contains(hostile)));
}

#[test]
fn the_backstop_is_ninety_seconds_and_the_refresh_is_thirty() {
    // T044, as constants rather than as prose: a killed process may leave the
    // routes for at most one lifetime, and a live one re-arms twice per lifetime.
    let lifetime = route_repair::ROUTE_BACKSTOP_LIFETIME;
    // A PowerShell `TimeSpan` literal, hh:mm:ss.
    let parts: Vec<u64> = lifetime
        .split(':')
        .map(|p| p.parse::<u64>().expect("hh:mm:ss components are numbers"))
        .collect();
    assert_eq!(parts.len(), 3, "{lifetime} is not a TimeSpan literal");
    let seconds = parts[0] * 3600 + parts[1] * 60 + parts[2];
    assert_eq!(seconds, 90, "{lifetime} must read as 90 seconds");
    assert_eq!(
        route_repair::ROUTE_BACKSTOP_REFRESH_INTERVAL,
        Duration::from_secs(30)
    );
    assert!(
        route_repair::ROUTE_BACKSTOP_REFRESH_INTERVAL.as_secs() * 2 < seconds,
        "a live session must re-arm with margin, not at the deadline"
    );
}

#[test]
fn the_refresh_arms_only_scoped_entries_and_never_deletes() {
    let lifetime = route_repair::ROUTE_BACKSTOP_LIFETIME;
    let wants = format!("-ValidLifetime '{lifetime}'");
    let prefers = format!("-PreferredLifetime '{lifetime}'");
    let commands = lifetime_refresh_commands(&journal());
    assert_eq!(commands.len(), 4, "same scoping rule as the removal");
    for command in &commands {
        assert!(command.contains("Set-NetRoute"), "{command}");
        assert!(command.contains("Where-Object"), "{command}");
        assert!(command.contains(&wants), "lifetime missing: {command}");
        assert!(
            command.contains(&prefers),
            "preferred lifetime missing: {command}"
        );
        assert!(
            !command.contains("Remove-NetRoute"),
            "the refresh must never delete: {command}"
        );
    }
    // A journal with nothing to scope yields nothing, so the refresh loop launches
    // no process at all rather than touching a stranger's route.
    assert!(lifetime_refresh_commands(&RouteJournal::default()).is_empty());
}

#[test]
fn the_refresh_block_is_one_spawn_too() {
    let script = powershell_script(&lifetime_refresh_commands(&journal()));
    assert_eq!(script.matches("$ErrorActionPreference").count(), 1);
}
