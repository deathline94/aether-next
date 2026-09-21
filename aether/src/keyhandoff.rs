//! Receiving the configuration key over the child's stdin.
//!
//! The key used to travel in the engine's environment. Process environments are
//! readable by anything on the machine that can open the process (a crash
//! collector, a monitoring agent, another user's `Get-Process` on Windows with
//! the right privileges, `/proc/<pid>/environ` on Android with root or an
//! `adb`-attached debuggable build), and they survive for the whole lifetime of
//! the process. One line on the already-piped control stdin is the same bytes
//! with a much shorter exposure and no path for a bystander to read.

use std::io::BufRead;
use std::time::Duration;

use base64::Engine;
use zeroize::Zeroize;

use crate::error::{AetherError, Result};
use crate::runtime_env;

/// Set by the parent to say "the key follows on stdin, not in the environment".
pub const REQUEST_ENV: &str = "AETHER_CONFIG_KEY_STDIN";
/// Prefix of the first control-channel line that carries the key.
pub const LINE_PREFIX: &str = "key ";
/// Prefix of the second control-channel line: where the driver DLL lives.
pub const DLL_PREFIX: &str = "dll wintun ";

const HANDOFF_TIMEOUT: Duration = Duration::from_secs(10);

/// The Wintun path the verified parent named on the control channel.
///
/// Deliberately not an environment variable. `AETHER_WINTUN` used to be read
/// from the child's environment, which meant the *elevated* engine would
/// `LoadLibrary` whatever DLL any process able to influence its environment
/// pointed at — a token privilege escalation with a one-variable setup step. The
/// only ways to name the driver now are this line, from the parent that already
/// Authenticode-verified it, or the copy sitting next to `aether.exe`.
#[cfg(windows)]
static WINTUN_TOKEN: std::sync::OnceLock<std::path::PathBuf> = std::sync::OnceLock::new();

#[cfg(windows)]
pub fn wintun_dll_path() -> Option<std::path::PathBuf> {
    WINTUN_TOKEN.get().cloned()
}

/// Validate one handoff line and return the base64 key it carried.
pub fn parse_key_line(line: &str) -> Result<String> {
    let line = line.trim_end_matches(['\r', '\n']);
    let Some(value) = line.strip_prefix(LINE_PREFIX) else {
        return Err(AetherError::Other(format!(
            "expected a `{LINE_PREFIX}<base64>` handoff line on stdin"
        )));
    };
    let value = value.trim();
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(value)
        .map_err(|e| AetherError::Other(format!("config key handoff is not valid base64: {e}")))?;
    if decoded.len() != 32 {
        return Err(AetherError::Other(format!(
            "config key handoff must be 32 bytes (got {})",
            decoded.len()
        )));
    }
    Ok(value.to_string())
}

/// Validate the driver-path handoff line. No existence or shape check happens
/// here: the path is only a *name*, and [`crate::tun_win`] is what decides
/// whether it is inside the allow-listed roots.
pub fn parse_dll_line(line: &str) -> Result<String> {
    let line = line.trim_end_matches(['\r', '\n']);
    let Some(value) = line.strip_prefix(DLL_PREFIX) else {
        return Err(AetherError::Other(format!(
            "expected a `{DLL_PREFIX}<path>` handoff line on stdin"
        )));
    };
    let value = value.trim();
    if value.is_empty() || value.len() > 4096 || value.contains('\0') {
        return Err(AetherError::Other(format!(
            "wintun handoff path is empty, over-long ({} bytes) or contains a NUL",
            value.len()
        )));
    }
    Ok(value.to_string())
}

fn read_preamble_line(what: &str) -> Result<String> {
    // A blocking `read_line` cannot be interrupted, so it runs on its own thread
    // and the caller waits with a deadline: a parent that opted in and then
    // never wrote would otherwise hang startup forever with no diagnostic.
    let (tx, rx) = std::sync::mpsc::channel::<std::io::Result<String>>();
    std::thread::Builder::new()
        .name("aether-handoff-reader".into())
        .spawn(move || {
            let mut line = String::new();
            let mut stdin = std::io::stdin().lock();
            match stdin.read_line(&mut line) {
                Ok(0) => {
                    let _ = tx.send(Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "control stdin closed before the handoff line arrived",
                    )));
                }
                Ok(_) => {
                    let _ = tx.send(Ok(line));
                }
                Err(e) => {
                    let _ = tx.send(Err(e));
                }
            }
        })
        .map_err(|e| AetherError::Other(format!("cannot start handoff reader: {e}")))?;

    match rx.recv_timeout(HANDOFF_TIMEOUT) {
        Ok(Ok(line)) => Ok(line),
        Ok(Err(e)) => Err(AetherError::Other(format!("{what} read failed: {e}"))),
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => Err(AetherError::Other(format!(
            "{REQUEST_ENV}=1 but no {what} line arrived within {:?}",
            HANDOFF_TIMEOUT
        ))),
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
            Err(AetherError::Other(format!("{what} reader died")))
        }
    }
}

/// Read the key — and, in TUN mode, the driver path — from stdin when the parent
/// asked for that handoff route, and install the key into [`runtime_env`] so the
/// single-reader rule still holds.
///
/// A no-op when a key is already present (an explicit environment variable still
/// works, which keeps the CLI usable) or when the parent did not opt in.
pub fn receive_if_requested() -> Result<()> {
    if !runtime_env::flag(REQUEST_ENV) {
        return Ok(());
    }
    if runtime_env::var("AETHER_CONFIG_KEY").is_some() {
        log::debug!("[keyhandoff] key already present in the environment; ignoring stdin request");
        return Ok(());
    }

    let mut key = parse_key_line(&read_preamble_line("key")?)?;
    runtime_env::set("AETHER_CONFIG_KEY", &key);
    key.zeroize();
    log::debug!("[keyhandoff] configuration key received over stdin");

    // The order is part of the protocol: the GUI writes the key line, then the
    // driver line iff it started the engine in TUN mode. Anything else and the
    // two sides disagree about how many preamble lines exist.
    #[cfg(windows)]
    if crate::tun_win::enabled() {
        let raw = parse_dll_line(&read_preamble_line("wintun")?)?;
        if WINTUN_TOKEN.set(std::path::PathBuf::from(raw)).is_err() {
            return Err(AetherError::Other("wintun handoff delivered twice".into()));
        }
        log::debug!("[keyhandoff] wintun path received over stdin");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_valid_line_installs_a_32_byte_key() {
        let b64 = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
        assert_eq!(parse_key_line(&format!("key {b64}\n")).unwrap(), b64);
        assert_eq!(parse_key_line(&format!("key {b64}")).unwrap(), b64);
    }

    #[test]
    fn anything_that_is_not_a_key_line_is_rejected() {
        assert!(parse_key_line("shutdown\n").is_err());
        assert!(parse_key_line("\n").is_err());
        assert!(parse_key_line("key not-base64!!").is_err());
        // A 16-byte key would decrypt nothing useful and silently mis-key the
        // config, so it must be refused at the door.
        let short = base64::engine::general_purpose::STANDARD.encode([1u8; 16]);
        let err = parse_key_line(&format!("key {short}")).unwrap_err();
        assert!(err.to_string().contains("32 bytes"), "{err}");
    }

    #[test]
    fn a_dll_line_carries_the_parents_path_verbatim() {
        assert_eq!(
            parse_dll_line("dll wintun C:\\Program Files\\Aether\\wintun.dll\n").unwrap(),
            r"C:\Program Files\Aether\wintun.dll"
        );
    }

    #[test]
    fn a_dll_line_that_is_not_a_path_is_rejected() {
        assert!(parse_dll_line("key abc\n").is_err(), "wrong token");
        assert!(parse_dll_line("dll wintun \n").is_err(), "empty path");
        assert!(parse_dll_line("dll wintun a\0b").is_err(), "NUL inside the path");
        assert!(
            parse_dll_line(&format!("dll wintun {}", "x".repeat(5000))).is_err(),
            "absurd length"
        );
        assert!(parse_dll_line("shutdown\n").is_err(), "a control command is not a path");
    }
}
