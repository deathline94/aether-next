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
