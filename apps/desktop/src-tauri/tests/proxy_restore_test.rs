#[cfg(windows)]
#[link(name = "resource", kind = "static")]
extern "C" {}

use aether_desktop_lib::windows_proxy::{verify_readback_values, ProxySnapshot};

fn snap(
    enabled: u32,
    server: Option<&str>,
    bypass: Option<&str>,
    pac: Option<&str>,
) -> ProxySnapshot {
    ProxySnapshot {
        enabled,
        server: server.map(str::to_string),
        bypass: bypass.map(str::to_string),
        auto_config_url: pac.map(str::to_string),
    }
}

/// `verify_readback_values` takes two snapshots, so a test cannot pass by
/// forgetting to supply one of the four values.
fn verify(
    expected: &ProxySnapshot,
    enabled: u32,
    server: Option<&str>,
    bypass: Option<&str>,
    pac: Option<&str>,
) -> Result<(), aether_desktop_lib::CommandError> {
    verify_readback_values(expected, &snap(enabled, server, bypass, pac))
}

#[test]
fn test_proxy_snapshot_serialization_roundtrip() {
    let snapshot = snap(
        1,
        Some("127.0.0.1:8086"),
        Some("<local>;*.internal"),
        Some("https://corp/pac.js"),
    );

    let json = serde_json::to_string(&snapshot).expect("serialize snapshot");
    let deserialized: ProxySnapshot = serde_json::from_str(&json).expect("deserialize snapshot");

    assert_eq!(deserialized.enabled, 1);
    assert_eq!(deserialized.server.as_deref(), Some("127.0.0.1:8086"));
    assert_eq!(deserialized.bypass.as_deref(), Some("<local>;*.internal"));
    assert_eq!(
        deserialized.auto_config_url.as_deref(),
        Some("https://corp/pac.js"),
        "the PAC URL has to survive the journal round trip or disconnect cannot give it back"
    );
}

/// A recovery file written by an older build has no `autoConfigUrl`. The reader
/// that exists to undo a proxy must not fatal on a field it has never seen.
#[test]
fn a_recovery_file_from_an_older_build_still_restores() {
    let legacy = r#"{"enabled":1,"server":"127.0.0.1:8080","bypass":"<local>"}"#;
    let parsed: ProxySnapshot =
        serde_json::from_str(legacy).expect("a missing optional field must not fatal the reader");
    assert_eq!(parsed.enabled, 1);
    assert_eq!(parsed.server.as_deref(), Some("127.0.0.1:8080"));
    assert_eq!(parsed.auto_config_url, None);
}

#[test]
fn test_proxy_snapshot_empty_options() {
    let snapshot = snap(0, None, None, None);
    let json = serde_json::to_string(&snapshot).expect("serialize snapshot");
    let deserialized: ProxySnapshot = serde_json::from_str(&json).expect("deserialize snapshot");

    assert_eq!(deserialized.enabled, 0);
    assert!(deserialized.server.is_none());
    assert!(deserialized.bypass.is_none());
    assert!(deserialized.auto_config_url.is_none());
}

#[test]
fn test_readback_verification_all_match() {
    let snapshot = snap(1, Some("127.0.0.1:8080"), Some("<local>;*.corp"), None);
    assert!(verify(
        &snapshot,
        1,
        Some("127.0.0.1:8080"),
        Some("<local>;*.corp"),
        None
    )
    .is_ok());

    let snapshot_empty = snap(0, None, None, None);
    assert!(verify(&snapshot_empty, 0, None, None, None).is_ok());
}

#[test]
fn test_readback_verification_detects_proxy_enable_mismatch() {
    let snapshot = snap(0, None, None, None);
    let err = verify(&snapshot, 1, None, None, None).unwrap_err();
    assert!(err.message.contains("ProxyEnable read-back mismatch"));
}

#[test]
fn test_readback_verification_detects_proxy_server_mismatch() {
    let snapshot = snap(1, Some("127.0.0.1:8080"), None, None);

    let err1 = verify(&snapshot, 1, Some("127.0.0.1:9090"), None, None).unwrap_err();
    assert!(err1.message.contains("ProxyServer read-back mismatch"));

    let err2 = verify(&snapshot, 1, None, None, None).unwrap_err();
    assert!(err2.message.contains("ProxyServer read-back mismatch"));

    let snapshot_none = snap(0, None, None, None);
    let err3 = verify(&snapshot_none, 0, Some("127.0.0.1:8080"), None, None).unwrap_err();
    assert!(err3.message.contains("ProxyServer read-back mismatch"));
}

#[test]
fn test_readback_verification_detects_proxy_override_mismatch() {
    let snapshot = snap(1, None, Some("<local>"), None);

    let err1 = verify(&snapshot, 1, None, Some("different"), None).unwrap_err();
    assert!(err1.message.contains("ProxyOverride read-back mismatch"));

    let err2 = verify(&snapshot, 1, None, None, None).unwrap_err();
    assert!(err2.message.contains("ProxyOverride read-back mismatch"));

    let snapshot_none = snap(0, None, None, None);
    let err3 = verify(&snapshot_none, 0, None, Some("<local>"), None).unwrap_err();
    assert!(err3.message.contains("ProxyOverride read-back mismatch"));
}

/// The value that was not compared at all until it was also not snapshotted: a
/// PAC URL outranks `ProxyServer` in WinINet, so "still set" after a restore means
/// the machine is back on its old resolver and "gone" after apply means Aether is
/// really in the path.
#[test]
fn readback_verification_detects_the_pac_url_being_left_behind() {
    let snapshot = snap(1, Some("127.0.0.1:8080"), None, Some("https://corp/proxy.pac"));

    let err = verify(&snapshot, 1, Some("127.0.0.1:8080"), None, None).unwrap_err();
    assert!(
        err.message.contains("AutoConfigURL read-back mismatch"),
        "{err:?}"
    );

    // Restore wrote a different PAC than the one that was there.
    let wrong = verify(
        &snapshot,
        1,
        Some("127.0.0.1:8080"),
        None,
        Some("https://other/proxy.pac"),
    )
    .unwrap_err();
    assert!(wrong.message.contains("AutoConfigURL read-back mismatch"));

    assert!(verify(
        &snapshot,
        1,
        Some("127.0.0.1:8080"),
        None,
        Some("https://corp/proxy.pac")
    )
    .is_ok());
}

#[test]
fn test_recover_preserves_file_on_restore_failure() {
    let dir = std::env::temp_dir().join(format!("test_proxy_recover_fail_{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let path = dir.join("proxy_recovery.json");

    let snapshot = snap(1, Some("127.0.0.1:8080"), None, None);
    let data = serde_json::to_vec(&snapshot).unwrap();
    std::fs::write(&path, data).unwrap();
    assert!(path.exists());

    // Fails in restorer
    let res = aether_desktop_lib::windows_proxy::recover_internal(&path, |_| {
        Err(aether_desktop_lib::CommandError::new(
            "readback",
            "read-back mismatch simulated",
        ))
    });

    assert!(res.is_err());
    // File MUST be preserved
    assert!(
        path.exists(),
        "recovery file must not be deleted if restore/readback fails"
    );

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_dir(&dir);
}

#[test]
fn test_recover_deletes_file_on_restore_success() {
    let dir = std::env::temp_dir().join(format!("test_proxy_recover_ok_{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let path = dir.join("proxy_recovery.json");

    let snapshot = snap(0, None, None, None);
    let data = serde_json::to_vec(&snapshot).unwrap();
    std::fs::write(&path, data).unwrap();
    assert!(path.exists());

    let res = aether_desktop_lib::windows_proxy::recover_internal(&path, |_| Ok(()));

    assert!(matches!(res, Ok(true)), "restored file should report success");
    // File MUST be deleted
    assert!(
        !path.exists(),
        "recovery file must be deleted on successful restore"
    );

    let _ = std::fs::remove_dir(&dir);
}

#[test]
fn test_read_optional_reg_value_error_discrimination() {
    use std::io;

    // Success -> Some(val)
    let ok_res = aether_desktop_lib::windows_proxy::read_optional_reg_value(
        Ok("127.0.0.1:8080".to_string()),
        "ProxyServer",
    );
    assert_eq!(ok_res.unwrap().as_deref(), Some("127.0.0.1:8080"));

    // NotFound -> None (valid absence)
    let not_found_res = aether_desktop_lib::windows_proxy::read_optional_reg_value(
        Err(io::Error::new(io::ErrorKind::NotFound, "not found")),
        "ProxyServer",
    );
    assert_eq!(not_found_res, Ok(None));

    // PermissionDenied / AccessDenied -> Err (must NOT be treated as None!)
    let denied_err = aether_desktop_lib::windows_proxy::read_optional_reg_value(
        Err(io::Error::new(io::ErrorKind::PermissionDenied, "access denied")),
        "ProxyServer",
    )
    .unwrap_err();
    assert!(denied_err.message.contains("verify read ProxyServer: access denied"));

    // Other errors (e.g. BrokenPipe) -> Err
    let other_err = aether_desktop_lib::windows_proxy::read_optional_reg_value(
        Err(io::Error::new(io::ErrorKind::BrokenPipe, "pipe broken")),
        "ProxyOverride",
    )
    .unwrap_err();
    assert!(other_err
        .message
        .contains("verify read ProxyOverride: pipe broken"));
}
