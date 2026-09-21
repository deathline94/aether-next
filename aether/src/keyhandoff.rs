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

const HANDOFF_TIMEOUT: Duration = Duration::from_secs(10);

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

/// Read the key from stdin when the parent asked for that handoff route, and
/// install it into [`runtime_env`] so the single-reader rule still holds.
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

    // A blocking `read_line` cannot be interrupted, so it runs on its own thread
    // and the caller waits with a deadline: a parent that opted in and then
    // never wrote would otherwise hang startup forever with no diagnostic.
    let (tx, rx) = std::sync::mpsc::channel::<std::io::Result<String>>();
    std::thread::Builder::new()
        .name("aether-key-handoff".into())
        .spawn(move || {
            let mut line = String::new();
            let mut stdin = std::io::stdin().lock();
            match stdin.read_line(&mut line) {
                Ok(0) => {
                    let _ = tx.send(Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "control stdin closed before the key arrived",
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
        .map_err(|e| AetherError::Other(format!("cannot start key handoff reader: {e}")))?;

    let line = match rx.recv_timeout(HANDOFF_TIMEOUT) {
        Ok(Ok(line)) => line,
        Ok(Err(e)) => return Err(AetherError::Other(format!("key handoff read failed: {e}"))),
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
            return Err(AetherError::Other(format!(
                "{REQUEST_ENV}=1 but no key line arrived within {:?}",
                HANDOFF_TIMEOUT
            )))
        }
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
            return Err(AetherError::Other("key handoff reader died".into()))
        }
    };

    let mut key = parse_key_line(&line)?;
    runtime_env::set("AETHER_CONFIG_KEY", &key);
    key.zeroize();
    log::debug!("[keyhandoff] configuration key received over stdin");
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
}
