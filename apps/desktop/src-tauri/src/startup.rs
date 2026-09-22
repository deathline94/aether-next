//! The reporting channel that works before — or instead of — a webview.
//!
//! In a release build this binary is `windows_subsystem = "windows"`: there is no
//! console attached, so `eprintln!` on the startup path goes to a handle nobody
//! owns and a panic in `run()` used to leave *no diagnostic at all* — a double
//! click that did nothing, with nothing to attach to a bug report. Everything that
//! has to be visible when the window never appears is written here as well: an
//! append-only file under the app's own config directory, mirrored to stderr, and
//! (on Windows) a message box for the failures that stop the app entirely.

use std::io::Write as _;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Must match `identifier` in `tauri.conf.json`. The value is duplicated because a
/// startup failure can happen before any config-backed path resolver exists; if it
/// ever drifts, the only consequence is that this file lands in the fallback
/// directory instead, which is still a place a support request can ask for.
const APP_IDENTIFIER: &str = "app.aethernext";
const FILE_NAME: &str = "aether-startup.log";

/// Lines this process has written, so the noise stays bounded if the shell is
/// wedged in a loop that reports.
static LINES: AtomicUsize = AtomicUsize::new(0);
const LINE_LIMIT: usize = 500;

/// Where the startup log lives: the app's config directory when it can be derived,
/// the system temp directory otherwise.
fn log_file() -> Option<PathBuf> {
    let mut candidates: Vec<PathBuf> = Vec::new();
    #[cfg(windows)]
    if let Some(appdata) = std::env::var_os("APPDATA") {
        candidates.push(PathBuf::from(appdata).join(APP_IDENTIFIER));
    }
    #[cfg(target_os = "macos")]
    if let Some(home) = std::env::var_os("HOME") {
        candidates.push(
            PathBuf::from(home)
                .join("Library")
                .join("Application Support")
                .join(APP_IDENTIFIER),
        );
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    {
        let base = std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")));
        if let Some(base) = base {
            candidates.push(base.join(APP_IDENTIFIER));
        }
    }
    candidates.push(std::env::temp_dir().join(APP_IDENTIFIER));
    candidates
        .into_iter()
        .find(|dir| std::fs::create_dir_all(dir).is_ok() && PathBuf::from(dir).is_dir())
        .map(|dir| dir.join(FILE_NAME))
}

/// Append one timestamped line. Best-effort by design: this is the last resort, so
/// it must not fail, panic or recurse back into the caller.
pub(crate) fn note(message: &str) {
    if LINES.fetch_add(1, Ordering::Relaxed) >= LINE_LIMIT {
        return;
    }
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if let Some(path) = log_file() {
        // The path is resolved per write on purpose: `OpenOptions::append` against
        // a rotating/quarantining AV scanner is the failure this file exists to
        // record, and a cached handle would hide it.
        if let Ok(mut file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
        {
            // Seconds since the Unix epoch, stated once so the file is readable
            // without a formatter and no local-time claim is being made.
            let _ = writeln!(file, "[{stamp}s] {message}");
            let _ = file.flush();
        }
    }
    let _ = writeln!(std::io::stderr(), "[aether] {message}");
    let _ = std::io::stderr().flush();
}

/// A failure that means there is no running app. Report it through every channel
/// that can survive that, then leave with a non-zero status.
pub(crate) fn report_and_exit(what: &str, detail: &str) -> ! {
    let message = format!("{what}: {detail}");
    note(&message);
    note(&format!(
        "no window was created; this message and the lines above are in {}",
        log_file()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "<no writable log directory>".into())
    ));
    #[cfg(windows)]
    show_message_box(&message);
    std::process::exit(1);
}

#[cfg(windows)]
fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

/// The one thing a user cannot miss on a machine where the app did not start.
///
/// `MB_SYSTEMMODAL` because there is no window of ours to be the owner, and
/// `MB_SETFOREGROUND` because a startup failure that appears behind another window
/// is a startup failure nobody sees.
#[cfg(windows)]
fn show_message_box(message: &str) {
    use std::ptr;
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        MessageBoxW, MB_ICONERROR, MB_OK, MB_SETFOREGROUND, MB_SYSTEMMODAL,
    };

    let body = wide(message);
    let title = wide("Aether Next could not start");
    unsafe {
        MessageBoxW(
            ptr::null_mut(),
            body.as_ptr(),
            title.as_ptr(),
            MB_OK | MB_ICONERROR | MB_SETFOREGROUND | MB_SYSTEMMODAL,
        );
    }
}

#[cfg(not(windows))]
fn show_message_box(_message: &str) {}
