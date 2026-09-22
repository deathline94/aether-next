//! An older config file must not be a reason to forget the newer settings.

// The test exe needs the shell's embedded application manifest to start on Windows.
#[cfg(windows)]
#[link(name = "resource", kind = "static")]
extern "C" {}

use aether_desktop_lib::{IpVersion, Protocol, RoutingMode, ScanMode, Settings, TransportKind};
use serde_json::Value;

/// `Settings` gained fields over releases (`peer`, the QUIC fragmentation pair, the
/// jitter bounds). Without a container-level default, a config written by an older
/// build failed to deserialise *entirely*: the shell reported a hydration failure,
/// the UI ran on `defaults`, and the first save wrote the user's protocol, ports
/// and obfuscation choices off the disk. The bug only bites after an upgrade, which
/// is why it survived every previous release.
#[test]
fn a_config_from_an_older_release_loads_and_keeps_what_it_declares() {
    let older = r#"{"protocol":"gool","transport":"h2","scanMode":"stealth","ipVersion":"v4",
        "noize":"off","noizeJc":5,"noizeJmin":50,"noizeJmax":128,"routingMode":"system-proxy",
        "socksPort":1080,"httpPort":18080,"startMinimized":false,"launchAtLogin":true,
        "enginePath":""}"#;
    let settings: Settings =
        serde_json::from_str(older).expect("a pre-QUIC-frag config must still load");
    assert_eq!(settings.protocol, Protocol::Gool);
    assert_eq!(settings.http_port, 18080);
    assert!(
        settings.launch_at_login,
        "the flag the user set survives the upgrade"
    );
    // The fields that file predates come from `Default`, not from nothing.
    assert_eq!(settings.scan_mode, ScanMode::Stealth);
    assert_eq!(settings.noize_jmax, 128);
    let defaults = Settings::default();
    assert_eq!(
        settings.quic_initial_frag, defaults.quic_initial_frag,
        "an absent field takes the documented default"
    );
    assert_eq!(
        settings.peer, "",
        "and a forced peer stays unset, not garbage"
    );
}

#[test]
fn a_full_round_trip_loses_nothing() {
    let original = Settings {
        protocol: Protocol::Masque,
        http_port: 18081,
        quic_initial_frag: true,
        quic_initial_frag_size: 128,
        noize: "custom".into(),
        noize_jmax: 2048,
        ..Settings::default()
    };
    let text = serde_json::to_string(&original).expect("serialise");
    let back: Settings = serde_json::from_str(&text).expect("deserialise");
    assert_eq!(back.http_port, original.http_port);
    assert_eq!(back.quic_initial_frag, original.quic_initial_frag);
    assert_eq!(back.quic_initial_frag_size, original.quic_initial_frag_size);
    assert_eq!(back.noize_jmax, original.noize_jmax);
}

/// The opposite failure: a file whose *known* fields are all wrong types must not
/// be papered over — `serde(default)` applies to missing fields, not to invalid
/// ones, or a corrupt config would silently rewrite itself to defaults.
#[test]
fn a_field_of_the_wrong_type_is_still_an_error() {
    let bad = r#"{"protocol":"masque","httpPort":"not a port"}"#;
    serde_json::from_str::<Settings>(bad)
        .expect_err("a present-but-invalid value must not be replaced by a default");
}

/// The enums replaced string allow-lists, and the React app was not touched.
/// That only holds if the strings on the wire are the ones it already sends, so
/// pin them: a rename of a variant is a silent config-format break the type
/// system cannot see.
#[test]
fn the_vocabulary_serialises_as_the_strings_the_ui_already_sends() {
    let settings = Settings {
        protocol: Protocol::Wireguard,
        transport: TransportKind::H3,
        scan_mode: ScanMode::Ironclad,
        ip_version: IpVersion::Dual,
        routing_mode: RoutingMode::ProxyOnly,
        ..Settings::default()
    };
    let json: Value = serde_json::to_value(&settings).expect("serialise");
    assert_eq!(json["protocol"], "wireguard");
    assert_eq!(json["transport"], "h3");
    assert_eq!(json["scanMode"], "ironclad");
    // The Scanner's and the Settings row's own spelling for "probe both
    // families" — the value the old allow-list rejected while the UI offered it.
    assert_eq!(json["ipVersion"], "both");
    assert_eq!(json["routingMode"], "proxy-only");
}

#[test]
fn every_default_is_the_string_the_previous_allow_list_defaulted_to() {
    let json: Value = serde_json::to_value(Settings::default()).expect("serialise");
    assert_eq!(json["protocol"], "masque");
    assert_eq!(json["transport"], "h2");
    assert_eq!(json["scanMode"], "balanced");
    assert_eq!(json["ipVersion"], "v4");
    assert_eq!(json["routingMode"], "system-proxy");
}

/// A stale file is not a load error, and a legacy spelling is not a different
/// choice: both go through the same parse the child's environment is built from,
/// so "what the engine was told" and "what the row shows" cannot drift.
#[test]
fn legacy_spellings_load_and_unknown_ones_fall_back_instead_of_failing() {
    let legacy = r#"{"ipVersion":"dual","scanMode":"DEEP ","protocol":"WARP","routingMode":"tun"}"#;
    let settings: Settings = serde_json::from_str(legacy)
        .expect("a legacy spelling must not turn the user's config into a load error");
    assert_eq!(settings.ip_version, IpVersion::Dual);
    assert_eq!(
        settings.scan_mode,
        ScanMode::Thorough,
        "trimmed and case-folded"
    );
    assert_eq!(settings.protocol, Protocol::Warp);
    assert_eq!(settings.routing_mode, RoutingMode::Tun);

    // `"thorogh"` was a legal value in the allow-list. Now it names nothing, so it
    // reads as the default the `#[serde(default)]` path produced — not as a
    // rejection of the whole file, and not as a mode that does not exist.
    let typo = r#"{"scanMode":"thorogh","ipVersion":"auto-detect","protocol":"teleport"}"#;
    let settings: Settings =
        serde_json::from_str(typo).expect("an unknown value is a stale file, not a corrupt one");
    assert_eq!(settings.scan_mode, ScanMode::default());
    assert_eq!(settings.ip_version, IpVersion::default());
    assert_eq!(settings.protocol, Protocol::default());

    // `"both"` reaches the engine as the string it parses, whatever the variant is
    // called in Rust.
    assert_eq!(IpVersion::Dual.as_str(), "both");
    assert_eq!(ScanMode::parse("thorogh"), None);
}

/// A damaged file used to decode into `Settings::default()`, and the page's
/// debounced autosave then wrote those defaults back over the user's real
/// protocol / ports / obfuscation. The load has to fail for the persist effect to
/// have anything to gate on.
#[test]
fn a_damaged_settings_file_is_refused_rather_than_replaced_by_defaults() {
    let err =
        aether_desktop_lib::decode_settings_text(r#"{"protocol":"masque","httpPort":"18a20"}"#)
            .expect_err("a field that is not the type it claims must not decode");
    let json = serde_json::to_value(&err).expect("errors carry their code over IPC");
    assert_eq!(json["code"], "settings_corrupt");
    assert_eq!(json["field"], "settings");
    assert!(
        json["message"]
            .as_str()
            .unwrap_or_default()
            .contains("refusing to overwrite"),
        "the message has to say what will not be done: {json}"
    );
}

#[test]
fn an_empty_or_truncated_file_is_corruption_but_an_absent_one_is_not() {
    assert!(aether_desktop_lib::decode_settings_text("").is_err());
    assert!(aether_desktop_lib::decode_settings_text("{").is_err());
    // A whole, valid document — including one that relies on the container default
    // for every field — still loads.
    assert!(aether_desktop_lib::decode_settings_text("{}").is_ok());
}

fn scratch_dir(tag: &str) -> std::path::PathBuf {
    static COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let dir = std::env::temp_dir().join(format!(
        "aether-{tag}-{}-{nanos}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).expect("scratch directory");
    dir
}

/// The writers used to share one hardcoded name — `settings.json.tmp`,
/// `proxy-recovery.json.tmp` — with `fs::write` and no flush. Any second writer
/// (an autosave during a connect) overwrote the first one's temp, and the rename
/// then published whichever bytes happened to be there.
#[test]
fn an_atomic_write_leaves_a_foreign_temporary_file_beside_its_target_alone() {
    let dir = scratch_dir("atomic");
    let target = dir.join("settings.json");
    let foreign = dir.join("settings.json.tmp");
    std::fs::write(&foreign, b"someone else's bytes").expect("seed temp");
    std::fs::write(&target, b"original").expect("seed target");

    aether_desktop_lib::write_atomic(&target, b"replacement").expect("atomic write");

    assert_eq!(
        std::fs::read(&target).unwrap().as_slice(),
        b"replacement".as_slice()
    );
    assert_eq!(
        std::fs::read(&foreign).unwrap().as_slice(),
        b"someone else's bytes".as_slice(),
        "the old code wrote here and renamed it over the target"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn an_atomic_write_that_fails_leaves_no_temporary_behind() {
    let dir = scratch_dir("atomic-fail");
    let target = dir.join("missing-subdir").join("proxy-recovery.json");
    assert!(aether_desktop_lib::write_atomic(&target, b"x").is_err());
    assert!(!dir.join("missing-subdir").exists(), "no temp may survive");
    let _ = std::fs::remove_dir_all(&dir);
}
