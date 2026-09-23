//! The Windows system-proxy integration: the registry journal, its HKCU mirror,
//! the read-back verification every write is checked against, and the restore a
//! crash cannot skip.

/// Only allow safe host tokens into Windows ProxyOverride (no `;` injection).
pub fn sanitize_proxy_bypass_host(endpoint: &str) -> Option<String> {
    let trimmed = endpoint.trim();
    let host = if let Some(rest) = trimmed.strip_prefix('[') {
        // Bracketed IPv6: `[::1]` or `[::1]:8080`. The port lives *outside* the
        // brackets, so the plain `rsplit_once(':')` below would have cut the
        // address itself in half.
        let (addr, suffix) = rest.split_once(']')?;
        let port_is_well_formed = suffix.is_empty()
            || (suffix.len() > 1
                && suffix.starts_with(':')
                && suffix[1..].bytes().all(|b| b.is_ascii_digit()));
        if !port_is_well_formed {
            return None;
        }
        addr
    } else {
        match trimmed.rsplit_once(':') {
            // `host:port` — but only when the head holds no colon of its own.
            // A bare, unbracketed IPv6 address (`2001:db8::1`, no port at all)
            // used to come back as `2001:db8:`, i.e. a wrong host written into
            // the system bypass list.
            Some((head, port))
                if !head.is_empty()
                    && !head.contains(':')
                    && !port.is_empty()
                    && port.bytes().all(|b| b.is_ascii_digit()) =>
            {
                head
            }
            _ => trimmed,
        }
    };
    let host = host.trim();
    if host.is_empty() || host.len() > 253 || host.ends_with(':') {
        return None;
    }
    // This character class *is* the filter. `;`, `<` and `>` — and every other
    // delimiter ProxyOverride could mis-parse — are not in it, so they need no
    // separate (and unreachable) `contains` checks beside it.
    let allowed = host
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':' | '_'));
    allowed.then(|| host.to_string())
}

/// The registry journal and its mirror.
///
/// `#[cfg(windows)]` because everything below is `HKCU\Software\...\Internet
/// Settings` traffic and the `winreg`/`windows-sys` dependencies behind it are
/// declared under `[target.'cfg(windows)'.dependencies]`: an ungated module here
/// would make the shell unbuildable for every other target, which is exactly how
/// the cross-platform `--repair-proxy` reading came to be pointless.
#[cfg(windows)]
pub mod windows_proxy {
    use crate::CommandError;

    use serde::{Deserialize, Serialize};
    use std::io;
    use std::path::Path;
    use windows_sys::Win32::Networking::WinInet::{
        InternetSetOptionW, INTERNET_OPTION_REFRESH, INTERNET_OPTION_SETTINGS_CHANGED,
    };
    use winreg::{enums::HKEY_CURRENT_USER, RegKey};

    #[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
    pub struct ProxySnapshot {
        pub enabled: u32,
        pub server: Option<String>,
        pub bypass: Option<String>,
        /// The PAC URL, which WinINet honours *ahead* of `ProxyServer`. It was not
        /// part of the snapshot at all, so enabling Aether on a machine with a
        /// corporate PAC left the PAC in charge — traffic went direct while the UI
        /// reported the proxy as active — and disconnecting deleted a `ProxyServer`
        /// that had been ours for the whole session.
        ///
        /// `#[serde(default)]`: a recovery file written by an older build has no
        /// such field, and a missing optional field must not fatal the read that is
        /// trying to undo the proxy.
        #[serde(default)]
        pub auto_config_url: Option<String>,
    }

    /// `ProxyEnable` absent is a real state ("this profile never enabled a proxy"),
    /// so it maps to 0. Any *other* read failure must propagate: `unwrap_or(0)`
    /// turned a transient registry error into "the user's proxy was off", which the
    /// restore path then honoured by switching a live proxy off permanently.
    fn read_enable(key: &RegKey) -> Result<u32, CommandError> {
        match key.get_value::<u32, _>("ProxyEnable") {
            Ok(v) => Ok(v),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(0),
            Err(e) => Err(format!("read ProxyEnable: {e}").into()),
        }
    }

    fn key() -> io::Result<RegKey> {
        RegKey::predef(HKEY_CURRENT_USER).open_subkey_with_flags(
            "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
            winreg::enums::KEY_READ | winreg::enums::KEY_SET_VALUE,
        )
    }

    fn refresh() {
        unsafe {
            InternetSetOptionW(
                std::ptr::null_mut(),
                INTERNET_OPTION_SETTINGS_CHANGED,
                std::ptr::null_mut(),
                0,
            );
            InternetSetOptionW(
                std::ptr::null_mut(),
                INTERNET_OPTION_REFRESH,
                std::ptr::null_mut(),
                0,
            );
        }
    }

    /// The four registry values that say "Aether owns the proxy right now".
    ///
    /// One definition, used by the writer, by the 30 s coherence check and by any
    /// later re-assert. Having the expectation computed in two places is how a
    /// checker ends up validating a string the writer never wrote.
    pub fn applied_expectation(port: u16, endpoint: Option<&str>) -> ProxySnapshot {
        let mut bypass = String::from("localhost;127.*;<local>");
        if let Some(ep) = endpoint {
            if let Some(host) = super::sanitize_proxy_bypass_host(ep) {
                bypass.push(';');
                bypass.push_str(&host);
            }
        }
        ProxySnapshot {
            enabled: 1,
            server: Some(format!("http=127.0.0.1:{port};https=127.0.0.1:{port}")),
            bypass: Some(bypass),
            // We deleted it on purpose; it must stay deleted while we own the proxy.
            auto_config_url: None,
        }
    }

    /// Read the proxy state as it is right now. Every read is hard-fail: a snapshot
    /// that silently lost a value is a snapshot that will delete that value on
    /// restore.
    fn read_snapshot(key: &RegKey) -> Result<ProxySnapshot, CommandError> {
        Ok(ProxySnapshot {
            enabled: read_enable(key)?,
            server: read_optional_reg_value(key.get_value("ProxyServer"), "ProxyServer")?,
            bypass: read_optional_reg_value(key.get_value("ProxyOverride"), "ProxyOverride")?,
            auto_config_url: read_optional_reg_value(
                key.get_value("AutoConfigURL"),
                "AutoConfigURL",
            )?,
        })
    }

    /// What the registry says now, for the coherence check and for reports.
    pub fn read_current() -> Result<ProxySnapshot, CommandError> {
        read_snapshot(&key()?)
    }

    /// A connection's own proxy settings, decoded far enough to *detect* a
    /// conflict with the per-user proxy this module owns.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct PerConnectionProxy {
        pub connection: String,
        /// The proxy server, or the PAC URL when the connection is script-driven.
        pub effective: String,
        pub via_script: bool,
    }

    const DEFAULT_CONNECTION_SETTINGS: &str = "DefaultConnectionSettings";
    /// `ProxySettingsFlag`: bit 0 use a proxy server, bit 1 auto-detect, bit 2 use
    /// a script. Any of the three takes the connection out of "direct" and puts it
    /// ahead of the per-user values.
    const FLAG_USE_PROXY: u32 = 0x1;
    const FLAG_AUTO_DETECT: u32 = 0x2;
    const FLAG_USE_SCRIPT: u32 = 0x4;
    /// The string area begins at 1000; the header holds 4-byte version, 4 reserved,
    /// 4-byte flags, then u16 offsets for ProxyServer / ProxyBypass / ProxyPAC.
    const STRING_AREA: usize = 1000;
    const SERVER_AT: usize = 12;
    const PAC_AT: usize = 16;

    /// Decode the proxy-relevant head of a `DefaultConnectionSettings` blob.
    ///
    /// `Ok(None)` means the connection is direct, so it cannot outrank anything.
    /// `Err` means the blob is not one this decoder can read, and the caller must
    /// report that rather than treat it as clean: a conflict it cannot see is a
    /// conflict it will deny.
    pub fn decode_connection_proxy(
        blob: &[u8],
        connection: &str,
    ) -> Result<Option<PerConnectionProxy>, String> {
        if blob.len() < 18 {
            return Err(format!(
                "{connection}: {DEFAULT_CONNECTION_SETTINGS} is {} bytes, too short to hold a proxy header",
                blob.len()
            ));
        }
        let head = |at: usize, width: usize| -> usize {
            if width == 4 {
                u32::from_le_bytes(blob[at..at + 4].try_into().expect("4 bytes")) as usize
            } else {
                u16::from_le_bytes(blob[at..at + 2].try_into().expect("2 bytes")) as usize
            }
        };
        let version = head(0, 4);
        // 5 (XP SP3) through 8 (Windows 10/11) share this header. Anything else is
        // a layout this decoder would be guessing at.
        if !(5..=8).contains(&version) {
            return Err(format!(
                "{connection}: {DEFAULT_CONNECTION_SETTINGS} version {version} is not one this decoder knows"
            ));
        }
        let flags = head(8, 4) as u32;
        let use_proxy = flags & FLAG_USE_PROXY != 0;
        let use_script = flags & FLAG_USE_SCRIPT != 0;
        let auto_detect = flags & FLAG_AUTO_DETECT != 0;
        if !use_proxy && !use_script && !auto_detect {
            return Ok(None);
        }
        // A script wins over a server in WinINet's own order of precedence, and
        // deleting our per-user proxy has no effect on either.
        let (slot, what) = if use_script {
            (PAC_AT, "PAC script")
        } else if use_proxy {
            (SERVER_AT, "proxy server")
        } else {
            // Auto-detect alone resolves through WPAD rather than a server the
            // caller can name. It is still a connection deciding its own route
            // while Aether claims to own it, so it is reported, not reasoned away.
            return Ok(Some(PerConnectionProxy {
                connection: connection.to_string(),
                effective: "auto-detect (WPAD)".to_string(),
                via_script: false,
            }));
        };
        let offset = head(slot, 2);
        if offset < STRING_AREA || offset >= blob.len() {
            return Err(format!(
                "{connection}: flags claim a {what} but its offset {offset} lies outside the blob's string area"
            ));
        }
        let end = blob[offset..]
            .iter()
            .position(|b| *b == 0)
            .ok_or_else(|| format!("{connection}: the {what} string is not terminated"))?;
        let value = String::from_utf8_lossy(&blob[offset..offset + end]).into_owned();
        if value.trim().is_empty() {
            return Err(format!(
                "{connection}: flags claim a {what} but the string is empty — the connection's route cannot be told"
            ));
        }
        Ok(Some(PerConnectionProxy {
            connection: connection.to_string(),
            effective: value,
            via_script: use_script,
        }))
    }

    /// Which of this user's connections would ignore the proxy Aether just wrote.
    ///
    /// `HKCU\...\Internet Settings\Connections` is per-user, so this needs no
    /// elevation; it reads only.
    pub fn per_connection_conflicts() -> Result<Vec<PerConnectionProxy>, String> {
        let root = match RegKey::predef(HKEY_CURRENT_USER).open_subkey_with_flags(
            "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Connections",
            winreg::enums::KEY_READ,
        ) {
            Ok(root) => root,
            // No Connections key is a real state: nothing is configured
            // per-connection, so nothing can outrank the per-user values.
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(format!("open the Connections key: {e}")),
        };
        let mut out = Vec::new();
        for name in root.enum_keys().flatten() {
            // `get_raw_value`, not `get_value::<Vec<u8>>`: winreg has no
            // `FromRegValue` for bytes because a byte vector could be any of
            // REG_BINARY or REG_MULTI_SZ, and guessing which is exactly what this
            // read must not do.
            let value = match root
                .open_subkey(&name)
                .and_then(|k| k.get_raw_value(DEFAULT_CONNECTION_SETTINGS))
            {
                Ok(value) => value,
                // A connection folder without the value has no per-connection proxy
                // to conflict with; a folder we cannot open is a different matter.
                Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
                Err(e) => return Err(format!("{name}: read {DEFAULT_CONNECTION_SETTINGS}: {e}")),
            };
            if value.vtype != winreg::enums::RegType::REG_BINARY {
                return Err(format!(
                    "{name}: {DEFAULT_CONNECTION_SETTINGS} is {:?}, not REG_BINARY",
                    value.vtype
                ));
            }
            match decode_connection_proxy(&value.bytes, &name) {
                Ok(Some(conflict)) => out.push(conflict),
                Ok(None) => {}
                Err(why) => return Err(why),
            }
        }
        Ok(out)
    }

    #[cfg(test)]
    mod per_connection_tests {
        use super::*;

        /// A `DefaultConnectionSettings` blob laid out the way a real one is: a
        /// 1000-byte header, then the NUL-terminated ANSI strings the offsets in
        /// that header point at.
        fn blob(version: u32, flags: u32, server: Option<&str>, pac: Option<&str>) -> Vec<u8> {
            let mut head = vec![0u8; STRING_AREA];
            head[0..4].copy_from_slice(&version.to_le_bytes());
            head[8..12].copy_from_slice(&flags.to_le_bytes());
            let mut at = STRING_AREA;
            for (slot, value) in [(SERVER_AT, server), (PAC_AT, pac)] {
                let Some(value) = value else { continue };
                head[slot..slot + 2].copy_from_slice(&(at as u16).to_le_bytes());
                head.extend_from_slice(value.as_bytes());
                head.push(0);
                at += value.len() + 1;
            }
            head
        }

        #[test]
        fn a_connection_with_its_own_proxy_outranks_ours() {
            let b = blob(8, FLAG_USE_PROXY, Some("10.0.0.9:3128"), None);
            let found = decode_connection_proxy(&b, "Ethernet").unwrap();
            assert_eq!(
                Some(PerConnectionProxy {
                    connection: "Ethernet".into(),
                    effective: "10.0.0.9:3128".into(),
                    via_script: false,
                }),
                found
            );
        }

        #[test]
        fn a_connection_script_outranks_ours_too_and_is_named_as_one() {
            let b = blob(
                7,
                FLAG_USE_SCRIPT,
                Some("ignored:80"),
                Some("http://corp/pac.js"),
            );
            let found = decode_connection_proxy(&b, "VPN").unwrap().unwrap();
            assert!(found.via_script, "a PAC is not a proxy server");
            assert_eq!("http://corp/pac.js", found.effective);
        }

        #[test]
        fn a_direct_connection_is_not_a_conflict() {
            let b = blob(8, 0, Some("stale:1"), None);
            assert_eq!(None, decode_connection_proxy(&b, "WiFi").unwrap());
        }

        #[test]
        fn a_layout_this_decoder_does_not_know_is_a_problem_not_an_all_clear() {
            // Failing closed here is the point: "cannot tell" must not become
            // "nothing conflicts", which is what a default-on decode gave back.
            let b = blob(9, FLAG_USE_PROXY, Some("10.0.0.9:3128"), None);
            assert!(decode_connection_proxy(&b, "WiFi").is_err());
            assert!(decode_connection_proxy(&b[..12], "WiFi").is_err());
        }

        #[test]
        fn flags_that_claim_a_value_the_blob_does_not_carry_are_a_problem() {
            let mut b = blob(8, FLAG_USE_PROXY, None, None);
            // offset 12 left zeroed: inside the header, not the string area.
            assert!(decode_connection_proxy(&b, "WiFi").is_err());
            b = blob(8, FLAG_USE_PROXY, Some("   "), None);
            assert!(decode_connection_proxy(&b, "WiFi").is_err());
        }
    }

    /// Write `want` over the current values and confirm it stuck. Used when a third
    /// party (another VPN client, a login script, GPO) has changed the proxy out
    /// from under a session that still claims to own it.
    pub fn reassert(want: &ProxySnapshot) -> Result<(), CommandError> {
        let key = key()?;
        let server = want.server.clone().unwrap_or_default();
        let bypass = want.bypass.clone().unwrap_or_default();
        key.set_value("ProxyServer", &server)
            .map_err(CommandError::from)?;
        key.set_value("ProxyOverride", &bypass)
            .map_err(CommandError::from)?;
        match want.auto_config_url.as_ref() {
            Some(v) => key
                .set_value("AutoConfigURL", v)
                .map_err(CommandError::from)?,
            None => match key.delete_value("AutoConfigURL") {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(format!("delete AutoConfigURL: {e}").into()),
            },
        }
        key.set_value("ProxyEnable", &want.enabled)
            .map_err(CommandError::from)?;
        let actual = read_snapshot(&key)?;
        verify_readback_values(want, &actual)?;
        refresh();
        Ok(())
    }

    pub fn enable(
        port: u16,
        endpoint: Option<&str>,
        recovery_path: Option<&Path>,
    ) -> Result<(ProxySnapshot, ProxySnapshot), (String, Option<ProxySnapshot>)> {
        let key = key().map_err(|e| (e.to_string(), None))?;
        let snapshot = read_snapshot(&key).map_err(|e| (e.message, None))?;
        // Registry mirror first: from this moment on, a deleted recovery file is
        // an inconvenience rather than an unrecoverable loss.
        write_mirror(&snapshot);
        if let Some(path) = recovery_path {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| (format!("proxy recovery directory: {e}"), None))?;
            }
            let json = serde_json::to_vec_pretty(&snapshot)
                .map_err(|e| (format!("proxy recovery encode: {e}"), None))?;
            // Exclusively-created temp + fsync before the rename: this file is the
            // only record of what the proxy was before Aether touched it, and a
            // fixed `proxy-recovery.json.tmp` name let a second writer (or a
            // reconnect while the first session was still bringing the proxy up)
            // interleave into it.
            crate::write_atomic(path, &json)
                .map_err(|e| (format!("proxy recovery write/commit: {e}"), None))?;
        }
        let applied = applied_expectation(port, endpoint);
        let result = (|| -> Result<(), CommandError> {
            let server = applied.server.clone().unwrap_or_default();
            let bypass = applied.bypass.clone().unwrap_or_default();
            key.set_value("ProxyServer", &server)
                .map_err(CommandError::from)?;
            key.set_value("ProxyOverride", &bypass)
                .map_err(CommandError::from)?;
            // Take the PAC out of the way while our proxy is active, but only
            // because it has been snapshotted: `restore` puts it back.
            match key.delete_value("AutoConfigURL") {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(format!("delete AutoConfigURL: {e}").into()),
            }
            key.set_value("ProxyEnable", &1u32)
                .map_err(CommandError::from)?;
            Ok(())
        })();
        if let Err(error) = result {
            clear_mirror();
            return match restore(snapshot.clone()) {
                Ok(()) => {
                    if let Some(path) = recovery_path {
                        let _ = std::fs::remove_file(path);
                    }
                    Err((error.message, None))
                }
                Err(rollback) => Err((
                    format!("{error}; rollback failed: {rollback}"),
                    Some(snapshot),
                )),
            };
        }
        refresh();
        // The caller keeps the *applied* values so it can tell, later, whether
        // something else changed the proxy underneath it.
        Ok((snapshot, applied))
    }

    /// Compare what the registry says now against what was intended, in full.
    ///
    /// Takes two snapshots rather than three loose parameters so that adding a
    /// field to `ProxySnapshot` cannot leave the comparison checking one value
    /// fewer than the writer wrote — which is how `AutoConfigURL` came to be
    /// restored, cleared and verified by nobody at the same time.
    pub fn verify_readback_values(
        expected: &ProxySnapshot,
        actual: &ProxySnapshot,
    ) -> Result<(), CommandError> {
        if actual.enabled != expected.enabled {
            return Err(format!(
                "ProxyEnable read-back mismatch: expected {}, got {}",
                expected.enabled, actual.enabled
            )
            .into());
        }
        for (name, want, got) in [
            ("ProxyServer", &expected.server, &actual.server),
            ("ProxyOverride", &expected.bypass, &actual.bypass),
            (
                "AutoConfigURL",
                &expected.auto_config_url,
                &actual.auto_config_url,
            ),
        ] {
            if want != got {
                return Err(format!(
                    "{name} read-back mismatch: expected {:?}, got {:?}",
                    want.as_deref(),
                    got.as_deref()
                )
                .into());
            }
        }
        Ok(())
    }

    pub fn restore(snapshot: ProxySnapshot) -> Result<(), CommandError> {
        let key = key().map_err(CommandError::from)?;
        match snapshot.server.as_ref() {
            Some(value) => key
                .set_value("ProxyServer", value)
                .map_err(CommandError::from)?,
            None => match key.delete_value("ProxyServer") {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(format!("delete ProxyServer: {e}").into()),
            },
        }
        match snapshot.bypass.as_ref() {
            Some(value) => key
                .set_value("ProxyOverride", value)
                .map_err(CommandError::from)?,
            None => match key.delete_value("ProxyOverride") {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(format!("delete ProxyOverride: {e}").into()),
            },
        }
        match snapshot.auto_config_url.as_ref() {
            Some(value) => key
                .set_value("AutoConfigURL", value)
                .map_err(CommandError::from)?,
            None => match key.delete_value("AutoConfigURL") {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(format!("delete AutoConfigURL: {e}").into()),
            },
        }
        key.set_value("ProxyEnable", &snapshot.enabled)
            .map_err(CommandError::from)?;

        // Read every value back before deciding the restore worked.
        let actual = ProxySnapshot {
            enabled: read_enable(&key)?,
            server: read_optional_reg_value(key.get_value("ProxyServer"), "ProxyServer")?,
            bypass: read_optional_reg_value(key.get_value("ProxyOverride"), "ProxyOverride")?,
            auto_config_url: read_optional_reg_value(
                key.get_value("AutoConfigURL"),
                "AutoConfigURL",
            )?,
        };

        verify_readback_values(&snapshot, &actual)?;
        // Only now: the mirror is what a later start restores *from*, and clearing
        // it before the values are back would lose the only remaining record.
        clear_mirror();

        refresh();
        Ok(())
    }

    pub fn read_optional_reg_value(
        res: io::Result<String>,
        val_name: &str,
    ) -> Result<Option<String>, CommandError> {
        match res {
            Ok(v) => Ok(Some(v)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(format!("verify read {val_name}: {e}").into()),
        }
    }

    /// What this session's proxy journal looks like in `HKCU`, next to the
    /// recovery *file*.
    ///
    /// The file is the primary record and the registry is the copy, because an
    /// antivirus real-time scan is known to quarantine a JSON file a process just
    /// wrote while leaving the process running. When that happens the *only* sign
    /// that Windows is still pointed at a port is the setting itself, and the next
    /// launch finds nothing to recover from: the user's browser keeps failing with
    /// no Aether running and no record of why.
    #[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
    pub struct JournalMirror {
        pub creator_pid: u32,
        pub written_unix: u64,
        pub snapshot: ProxySnapshot,
    }

    const JOURNAL_SUBKEY: &str = "Software\\AetherNext";
    const JOURNAL_VALUE: &str = "ProxyJournal";

    fn write_mirror(snapshot: &ProxySnapshot) {
        let mirror = JournalMirror {
            creator_pid: std::process::id(),
            written_unix: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            snapshot: snapshot.clone(),
        };
        let json = match serde_json::to_string(&mirror) {
            Ok(j) => j,
            Err(e) => {
                eprintln!("[proxy] cannot encode the registry journal mirror: {e}");
                return;
            }
        };
        match RegKey::predef(HKEY_CURRENT_USER)
            .create_subkey(JOURNAL_SUBKEY)
            .map(|(k, _)| k)
        {
            Ok(key) => {
                if let Err(e) = key.set_value::<String, _>(JOURNAL_VALUE, &json) {
                    eprintln!("[proxy] cannot write the registry journal mirror: {e}");
                }
            }
            Err(e) => eprintln!("[proxy] cannot open {JOURNAL_SUBKEY} for the journal mirror: {e}"),
        }
    }

    fn read_mirror() -> Option<JournalMirror> {
        let key = RegKey::predef(HKEY_CURRENT_USER)
            .open_subkey(JOURNAL_SUBKEY)
            .ok()?;
        let raw: String = key.get_value(JOURNAL_VALUE).ok()?;
        match serde_json::from_str(&raw) {
            Ok(m) => Some(m),
            Err(e) => {
                // Unparseable is not "restore with defaults": a mirror nobody can
                // read says nothing about what the previous session changed.
                eprintln!("[proxy] registry journal mirror is unreadable ({e}); clearing it");
                clear_mirror();
                None
            }
        }
    }

    fn clear_mirror() {
        if let Ok(key) = RegKey::predef(HKEY_CURRENT_USER).open_subkey(JOURNAL_SUBKEY) {
            let _ = key.delete_value(JOURNAL_VALUE);
        }
    }

    /// Whether a leftover mirror justifies restoring the proxy on this start.
    ///
    /// Kept free of I/O so the decision — and the case it exists for, "the file is
    /// gone, the session that made the change is dead" — is testable on any machine.
    pub fn decide_sweep(
        mirror: Option<&JournalMirror>,
        recovery_file_present: bool,
        holder_alive: bool,
    ) -> Sweep {
        if mirror.is_none() {
            // No mirror at all: the recovery file, if any, was already consumed by
            // the caller, and a proxy change with no record anywhere is a different
            // bug than the one this sweep exists for.
            return Sweep::Nothing;
        }
        if recovery_file_present {
            return Sweep::Nothing;
        }
        if holder_alive {
            // Another session owns the proxy right now. Restoring would take the
            // machine off a tunnel that is demonstrably up.
            return Sweep::Nothing;
        }
        Sweep::RestoreFromMirror
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Sweep {
        Nothing,
        /// The recovery file is gone, the mirror says a session changed the proxy,
        /// and the process that did it is no longer alive.
        RestoreFromMirror,
    }

    /// Is the pid recorded in the mirror still running? Only ever used to decide
    /// whether to *leave the proxy alone*, so an unknown answer means "alive".
    fn holder_alive(pid: u32) -> bool {
        if pid == 0 || pid == std::process::id() {
            return true;
        }
        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::System::Threading::{
            GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
        };
        // ` STILL_ACTIVE` is the exit code a running process reports; windows-sys
        // does not export the constant, and a magic 259 with no name is unreadable.
        const STILL_ACTIVE: u32 = 259;
        unsafe {
            let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
            if handle.is_null() {
                // Access denied means the process exists and is someone else's.
                return std::io::Error::last_os_error().raw_os_error() == Some(5);
            }
            let mut code = 0u32;
            let ok = GetExitCodeProcess(handle, &mut code);
            CloseHandle(handle);
            ok != 0 && code == STILL_ACTIVE
        }
    }

    /// Startup orphan sweep: restore from the mirror when the file was lost.
    pub fn sweep_orphan() -> Option<ProxySnapshot> {
        let mirror = read_mirror()?;
        match decide_sweep(Some(&mirror), false, holder_alive(mirror.creator_pid)) {
            Sweep::RestoreFromMirror => {
                eprintln!(
                "[proxy] recovery file missing but HKCU\\{JOURNAL_SUBKEY} still records a change \
                 by dead pid {}; restoring the proxy from the mirror",
                mirror.creator_pid
            );
                Some(mirror.snapshot)
            }
            Sweep::Nothing => None,
        }
    }

    /// Consume a recovery file: restore, and only then unlink. A restore that
    /// reports failure leaves the file in place, so the next start tries again.
    pub fn recover_internal<F: Fn(ProxySnapshot) -> Result<(), CommandError>>(
        path: &Path,
        restorer: F,
    ) -> Result<bool, CommandError> {
        if !path.exists() {
            return Ok(false);
        }
        let data = std::fs::read(path).map_err(CommandError::from)?;
        let snapshot: ProxySnapshot = serde_json::from_slice(&data).map_err(CommandError::from)?;
        restorer(snapshot)?;
        std::fs::remove_file(path).map_err(CommandError::from)?;
        Ok(true)
    }

    pub fn recover(path: &Path) -> Result<bool, CommandError> {
        recover_internal(path, restore)
    }
}
