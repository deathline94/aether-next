#[cfg(windows)]
#[link(name = "resource", kind = "static")]
extern "C" {}

use aether_desktop_lib::windows_proxy::ProxySnapshot;

#[test]
fn test_proxy_snapshot_serialization_roundtrip() {
    let snapshot = ProxySnapshot {
        enabled: 1,
        server: Some("127.0.0.1:8086".to_string()),
        bypass: Some("<local>;*.internal".to_string()),
    };

    let json = serde_json::to_string(&snapshot).expect("serialize snapshot");
    let deserialized: ProxySnapshot = serde_json::from_str(&json).expect("deserialize snapshot");

    assert_eq!(deserialized.enabled, 1);
    assert_eq!(deserialized.server.as_deref(), Some("127.0.0.1:8086"));
    assert_eq!(deserialized.bypass.as_deref(), Some("<local>;*.internal"));
}

#[test]
fn test_proxy_snapshot_empty_options() {
    let snapshot = ProxySnapshot {
        enabled: 0,
        server: None,
        bypass: None,
    };

    let json = serde_json::to_string(&snapshot).expect("serialize snapshot");
    let deserialized: ProxySnapshot = serde_json::from_str(&json).expect("deserialize snapshot");

    assert_eq!(deserialized.enabled, 0);
    assert!(deserialized.server.is_none());
    assert!(deserialized.bypass.is_none());
}

#[test]
fn test_readback_verification_all_match() {
    let snapshot = ProxySnapshot {
        enabled: 1,
        server: Some("127.0.0.1:8080".to_string()),
        bypass: Some("<local>;*.corp".to_string()),
    };

    let res = aether_desktop_lib::windows_proxy::verify_readback_values(
        &snapshot,
        1,
        Some("127.0.0.1:8080"),
        Some("<local>;*.corp"),
    );
    assert!(res.is_ok());

    let snapshot_empty = ProxySnapshot {
        enabled: 0,
        server: None,
        bypass: None,
    };

    let res_empty = aether_desktop_lib::windows_proxy::verify_readback_values(
        &snapshot_empty,
        0,
        None,
        None,
    );
    assert!(res_empty.is_ok());
}

#[test]
fn test_readback_verification_detects_proxy_enable_mismatch() {
    let snapshot = ProxySnapshot {
        enabled: 0,
        server: None,
        bypass: None,
    };

    let err = aether_desktop_lib::windows_proxy::verify_readback_values(
        &snapshot,
        1,
        None,
        None,
    ).unwrap_err();
    assert!(err.contains("ProxyEnable read-back mismatch"));
}

#[test]
fn test_readback_verification_detects_proxy_server_mismatch() {
    let snapshot = ProxySnapshot {
        enabled: 1,
        server: Some("127.0.0.1:8080".to_string()),
        bypass: None,
    };

    // Mismatched value
    let err1 = aether_desktop_lib::windows_proxy::verify_readback_values(
        &snapshot,
        1,
        Some("127.0.0.1:9090"),
        None,
    ).unwrap_err();
    assert!(err1.contains("ProxyServer read-back mismatch"));

    // Missing actual value
    let err2 = aether_desktop_lib::windows_proxy::verify_readback_values(
        &snapshot,
        1,
        None,
        None,
    ).unwrap_err();
    assert!(err2.contains("ProxyServer read-back mismatch"));

    // Expected None, but got Some
    let snapshot_none = ProxySnapshot {
        enabled: 0,
        server: None,
        bypass: None,
    };
    let err3 = aether_desktop_lib::windows_proxy::verify_readback_values(
        &snapshot_none,
        0,
        Some("127.0.0.1:8080"),
        None,
    ).unwrap_err();
    assert!(err3.contains("ProxyServer read-back mismatch"));
}

#[test]
fn test_readback_verification_detects_proxy_override_mismatch() {
    let snapshot = ProxySnapshot {
        enabled: 1,
        server: None,
        bypass: Some("<local>".to_string()),
    };

    let err1 = aether_desktop_lib::windows_proxy::verify_readback_values(
        &snapshot,
        1,
        None,
        Some("different"),
    ).unwrap_err();
    assert!(err1.contains("ProxyOverride read-back mismatch"));

    let err2 = aether_desktop_lib::windows_proxy::verify_readback_values(
        &snapshot,
        1,
        None,
        None,
    ).unwrap_err();
    assert!(err2.contains("ProxyOverride read-back mismatch"));

    let snapshot_none = ProxySnapshot {
        enabled: 0,
        server: None,
        bypass: None,
    };
    let err3 = aether_desktop_lib::windows_proxy::verify_readback_values(
        &snapshot_none,
        0,
        None,
        Some("<local>"),
    ).unwrap_err();
    assert!(err3.contains("ProxyOverride read-back mismatch"));
}

#[test]
fn test_recover_preserves_file_on_restore_failure() {
    let dir = std::env::temp_dir().join(format!("test_proxy_recover_fail_{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let path = dir.join("proxy_recovery.json");

    let snapshot = ProxySnapshot {
        enabled: 1,
        server: Some("127.0.0.1:8080".to_string()),
        bypass: None,
    };
    let data = serde_json::to_vec(&snapshot).unwrap();
    std::fs::write(&path, data).unwrap();
    assert!(path.exists());

    // Fails in restorer
    let res = aether_desktop_lib::windows_proxy::recover_internal(&path, |_| {
        Err("read-back mismatch simulated".to_string())
    });

    assert!(res.is_err());
    // File MUST be preserved
    assert!(path.exists(), "recovery file must not be deleted if restore/readback fails");

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_dir(&dir);
}

#[test]
fn test_recover_deletes_file_on_restore_success() {
    let dir = std::env::temp_dir().join(format!("test_proxy_recover_ok_{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let path = dir.join("proxy_recovery.json");

    let snapshot = ProxySnapshot {
        enabled: 0,
        server: None,
        bypass: None,
    };
    let data = serde_json::to_vec(&snapshot).unwrap();
    std::fs::write(&path, data).unwrap();
    assert!(path.exists());

    let res = aether_desktop_lib::windows_proxy::recover_internal(&path, |_| Ok(()));

    assert_eq!(res, Ok(true));
    // File MUST be deleted
    assert!(!path.exists(), "recovery file must be deleted on successful restore");

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
    assert_eq!(ok_res, Ok(Some("127.0.0.1:8080".to_string())));

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
    ).unwrap_err();
    assert!(denied_err.contains("verify read ProxyServer: access denied"));

    // Other errors (e.g. BrokenPipe) -> Err
    let other_err = aether_desktop_lib::windows_proxy::read_optional_reg_value(
        Err(io::Error::new(io::ErrorKind::BrokenPipe, "pipe broken")),
        "ProxyOverride",
    ).unwrap_err();
    assert!(other_err.contains("verify read ProxyOverride: pipe broken"));
}

