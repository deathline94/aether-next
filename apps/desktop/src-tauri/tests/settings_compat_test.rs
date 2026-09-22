//! An older config file must not be a reason to forget the newer settings.

// The test exe needs the shell's embedded application manifest to start on Windows.
#[cfg(windows)]
#[link(name = "resource", kind = "static")]
extern "C" {}

use aether_desktop_lib::Settings;

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
    assert_eq!(settings.protocol, "gool");
    assert_eq!(settings.http_port, 18080);
    assert!(settings.launch_at_login, "the flag the user set survives the upgrade");
    // The fields that file predates come from `Default`, not from nothing.
    assert_eq!(settings.scan_mode, "stealth");
    assert_eq!(settings.noize_jmax, 128);
    let defaults = Settings::default();
    assert_eq!(
        settings.quic_initial_frag, defaults.quic_initial_frag,
        "an absent field takes the documented default"
    );
    assert_eq!(settings.peer, "", "and a forced peer stays unset, not garbage");
}

#[test]
fn a_full_round_trip_loses_nothing() {
    let original = Settings {
        protocol: "masque".into(),
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
