//! CLI entry point logic, living in the library.
//!
//! This used to be the body of `src/main.rs`, which declared its **own** private
//! copy of all 30 modules (`mod account; mod config; ...`). Consequences:
//!
//! * `aether/tests/*` and `#[cfg(test)]` suites exercised the *library* copy,
//!   while the shipped binary was a second compilation of the same source — so a
//!   green test run said nothing about the executable users actually ran. The
//!   split was directly observable in test counts (78 lib vs 58 binary).
//! * Any module added to `lib.rs` was invisible to the binary until it was also
//!   added to `main.rs`, which is how `route_repair`/`trust` broke `--tests`.
//!
//! So `main.rs` is now a three-line shim and everything real lives here, where
//! it is compiled and tested exactly once.

use std::time::Duration;

use crate::engine_config::EngineConfig;
use crate::error::Result;
use crate::session_event::SessionEvent;

pub async fn run() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp_millis()
        .init();

    install_panic_guard();

    // The engine binary reported nothing about itself: only the shell exposed a
    // version, so a support thread could not ask the one component that matters
    // "which build are you". Read-only, and before anything can touch the host.
    if std::env::args().any(|a| a == "--version" || a == "-V") {
        println!("aether {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }

    // Read-only export, before anything can touch the host. The support path had
    // no machine-checkable answer to "what did the engine actually resolve?".
    if std::env::args().any(|a| a == "--diagnostics") {
        crate::diagnostics::print();
        return Ok(());
    }

    // Before the first spawned tool or loaded DLL, and before the route replay
    // below: pin the search order to `%WINDIR%\System32`.
    #[cfg(windows)]
    crate::win_exec::pin_dll_search_path()?;

    // Host-state repair, before anything else can touch the routing table.
    //
    // It used to live only inside the TUN bring-up, so an abandoned journal was
    // never replayed when the crash happened in system-proxy mode (or when the
    // user never enabled TUN again): the machine stayed black-holed through a
    // route owned by a process that no longer exists. The journal is
    // pid-guarded, so this is a no-op while a live engine holds the routes.
    #[cfg(windows)]
    {
        if std::env::args().any(|a| a == "--repair-routes") {
            crate::tun_win::recover_stale_routes();
            return Ok(());
        }
        if !crate::runtime_env::flag("AETHER_SCAN_ONLY") {
            crate::tun_win::recover_stale_routes();
        }
    }

    let session = crate::session::run_session(EngineConfig::from_env()?);
    let result = if crate::runtime_env::flag("AETHER_CONTROL_STDIN") {
        tokio::select! {
            result = session => result,
            _ = shutdown_request() => {
                log::info!("[+] graceful shutdown requested");
                // The envelope key is held in the process environment store so the
                // session can re-seal the identity file; on an explicit shutdown
                // there is no later session to serve, so drop the copy rather than
                // let it sit until the process ends.
                crate::keyhandoff::forget_key();
                Ok(())
            }
        }
    } else {
        session.await
    };

    if let Err(ref e) = result {
        let retryable = e.is_retryable();
        let message = match e {
            crate::error::AetherError::NoCleanEndpoint => {
                "No working gateway found. Try HTTP/2, another scan mode, or a different network."
                    .to_string()
            }
            other => other.to_string(),
        };
        // The code travels with the text so a failure can be identified without
        // matching a sentence, and the exit status separates "try again" from
        // "something is wrong with this configuration" — both used to be 1, which
        // left the supervising shell unable to tell a transient edge loss from a
        // bad identity no retry will ever fix.
        //
        // The `[-] session failed:` prefix stays byte-identical and keeps its
        // colon: src-tauri's log mirror matches and splits on exactly that string.
        log::error!("[-] session failed: {message} [{}]", e.code());
        crate::session_event::emit(SessionEvent::Error { message });
        use std::io::Write;
        let _ = std::io::stdout().flush();
        let _ = std::io::stderr().flush();
        // Give the parent shell a moment to read the terminal event before the
        // process disappears, otherwise the GUI sees a bare exit with no reason.
        tokio::time::sleep(Duration::from_millis(80)).await;
        std::process::exit(if retryable { 4 } else { 1 });
    }

    // Scan-only sessions finish on their own, but the control-stdin reader parks a
    // tokio::io::stdin() blocking read that blocks runtime shutdown and hangs the
    // process on exit — so the GUI never learns the scan ended and the Scanner tab
    // stays "active" until Stop is pressed. Scan-only touches no TUN/routes/proxy,
    // so exiting directly is safe here (and only here); connect() must still
    // return normally so the route/TUN teardown Drops run.
    if crate::runtime_env::flag("AETHER_SCAN_ONLY") {
        std::process::exit(if result.is_err() { 1 } else { 0 });
    }
    result
}

/// The only thing that ends the control wait: an explicit `shutdown` token.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum Control {
    Shutdown,
}

async fn shutdown_request() {
    use tokio::io::{AsyncBufReadExt, BufReader};

    let lines = BufReader::new(tokio::io::stdin()).lines();
    // The value says which of the two ended the wait; this arm's completion is
    // the signal, and it only ever happens on an explicit `shutdown`.
    watch_control(lines).await;
}

/// Read control-channel lines until an explicit `shutdown`.
///
/// End-of-input is **not** a shutdown. The parent writes the key handoff on this
/// same pipe and may close its write half the moment that is done — and the old
/// `while let Ok(Some(line))` loop simply ended on `None`, which returned from
/// `shutdown_request()`, won the `select!`, dropped the live session and exited 0.
/// A tunnel that looked healthy to the parent had been killed by the parent
/// finishing its own write. So EOF parks this arm forever and only the token
/// retires it.
async fn watch_control<R>(mut lines: tokio::io::Lines<R>) -> Control
where
    R: tokio::io::AsyncBufRead + Unpin,
{
    while let Ok(Some(line)) = lines.next_line().await {
        match line.trim().to_ascii_lowercase().as_str() {
            "shutdown" => return Control::Shutdown,
            // Cooperative cancel: let an in-flight scan finalise with its best
            // result (and persist it) instead of being dropped mid-work.
            "cancel" => crate::prober::request_scan_cancel(),
            other => {
                // An unrecognised control token used to be discarded silently, so
                // a shell/engine protocol mismatch was invisible on both ends.
                if !other.is_empty() {
                    log::warn!("[control] unrecognised stdin token {other:?}");
                }
            }
        }
    }
    log::info!("[control] stdin closed; keeping the session up (only `shutdown` retires it)");
    std::future::pending::<Control>().await
}

/// Install the process panic hook.
fn install_panic_guard() {
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let file = info
            .location()
            .map(|l| l.file().to_string())
            .unwrap_or_default();
        if is_netstack_panic(&file) {
            // Previously `log::debug!`, which is invisible at the default `info`
            // filter: the netstack task could die and the tunnel would simply stop
            // carrying traffic with nothing on screen to say so.
            log::error!("[netstack] recovered from a malformed segment: {info}");
        } else {
            default_hook(info);
        }
    }));
}

/// True when the panic came from our netstack or from smoltcp itself.
///
/// Path *components* are compared, not an arbitrary substring of the whole
/// panic payload: the old check was `location().file().contains("smoltcp")`,
/// which also matched any vendor directory or checkout whose path happened to
/// contain that text, muting real crashes in unrelated code.
fn is_netstack_panic(file: &str) -> bool {
    let file = file.replace('\\', "/");
    let segments: Vec<&str> = file.split('/').collect();

    // `crate/src/rest...` where `crate` is the bare name or its versioned
    // registry form (`smoltcp`, `smoltcp-0.12.0`). Still component-wise: a path
    // that merely *contains* the text somewhere, like
    // `build/smoltcp-helpers/src/lib.rs`, must not match.
    let in_crate = |name: &str, tail: &[&str]| {
        let want = tail.len() + 1;
        want <= segments.len()
            && segments.windows(want).any(|w| {
                (w[0] == name || w[0].strip_prefix(name).is_some_and(|r| r.starts_with('-')))
                    && &w[1..] == tail
            })
    };

    in_crate("smoltcp", &["src", "socket", "tcp.rs"])
        || in_crate("smoltcp", &["src", "socket", "udp.rs"])
        || in_crate("smoltcp", &["src", "iface", "mod.rs"])
        // Our own stack: cargo reports this as the relative "src/netstack.rs",
        // but an absolute path from a panic in a dependency build must also land.
        || segments.ends_with(&["src", "netstack.rs"])
}

#[cfg(test)]
mod tests {
    use super::{is_netstack_panic, watch_control, Control};
    use std::time::Duration;
    use tokio::io::{AsyncBufReadExt, BufReader};

    fn lines(text: &'static [u8]) -> tokio::io::Lines<BufReader<&'static [u8]>> {
        BufReader::new(text).lines()
    }

    /// The parent writes the key handoff on this pipe and is free to close its
    /// write half as soon as that lands. Ending the wait there used to win the
    /// `select!` in `run`, drop the live session and exit 0 — a silent tunnel
    /// kill, with a success code.
    #[tokio::test]
    async fn eof_on_the_control_pipe_does_not_shut_the_session_down() {
        let gone = tokio::time::timeout(Duration::from_millis(200), watch_control(lines(b"")))
            .await
            .is_ok();
        assert!(
            !gone,
            "an empty control pipe was treated as a shutdown request"
        );
    }

    /// A handoff line followed by EOF is the real sequence a parent performs.
    #[tokio::test]
    async fn a_handoff_line_then_eof_still_does_not_shut_it_down() {
        let input: &[u8] = b"key a2V5a2V5a2V5a2V5a2V5a2V5a2V5a2V5a2V5a2V5a2U=\n";
        let gone = tokio::time::timeout(Duration::from_millis(200), watch_control(lines(input)))
            .await
            .is_ok();
        assert!(
            !gone,
            "a token that is not `shutdown` ended the control wait"
        );
    }

    /// ... and the token that *is* a shutdown still works, so this is a
    /// distinction and not an unreachable arm.
    #[tokio::test]
    async fn only_shutdown_retires_the_control_wait() {
        let input: &[u8] = b"nonsense-token\n  SHUTDOWN  \nnever-read\n";
        let got = tokio::time::timeout(Duration::from_millis(200), watch_control(lines(input)))
            .await
            .expect("`shutdown` must end the wait");
        assert_eq!(got, Control::Shutdown);
    }

    #[test]
    fn netstack_panics_are_recognised_on_both_path_styles() {
        assert!(is_netstack_panic("src/netstack.rs"));
        assert!(is_netstack_panic("aether\\src\\netstack.rs"));
        assert!(is_netstack_panic(
            "/home/dev/.cargo/registry/src/index.crates.io-123/smoltcp-0.12.0/src/socket/tcp.rs"
        ));
    }

    #[test]
    fn unrelated_panics_are_not_muted() {
        // The substring bug: any path merely *containing* "smoltcp" silenced it.
        assert!(!is_netstack_panic("src/quic.rs"));
        assert!(!is_netstack_panic("build/smoltcp-helpers/src/lib.rs"));
        assert!(!is_netstack_panic("my_smoltcp_fork.rs"));
        assert!(!is_netstack_panic(""));
    }
}
