//! Locating the engine binary and preparing the child it launches: resource
//! resolution, the ambient-environment scrub, and the stdin handoff that carries
//! the master key and the driver path outside the process environment.
use crate::error::CommandError;
use crate::settings::{RoutingMode, Settings};
use crate::trust::validate_trusted_binary;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use tauri::{path::BaseDirectory, AppHandle, Manager};

pub(crate) fn resolve_resource(app: &AppHandle, name: &str) -> Option<PathBuf> {
    app.path()
        .resolve(name, BaseDirectory::Resource)
        .ok()
        .filter(|p| p.is_file())
}

/// Drop every `AETHER_*` variable this process inherited before spawning the
/// engine.
///
/// The child's environment used to be "ours plus the keys we set", which made
/// the whole `runtime_env` single-reader rule decorative: anything already in
/// the user's session — `AETHER_TUN`, `AETHER_CONFIG_KEY`, a kill-switch, a peer
/// override — reached the elevated process without the shell deciding it, and
/// `AETHER_CONFIG_KEY` in particular made the child skip the stdin handoff it was
/// promised. Enumerated rather than listed, so a new engine key cannot be
/// forgotten here.
pub(crate) fn scrub_ambient_engine_env(command: &mut Command) {
    for (key, _) in std::env::vars_os() {
        let name = key.to_string_lossy().into_owned();
        if name.to_ascii_uppercase().starts_with("AETHER_") {
            command.env_remove(name);
        }
    }
}

/// Write the engine's stdin preamble: the envelope key, and in TUN mode the one
/// path it is allowed to load the driver from.
///
/// A child process environment stays readable for the whole lifetime of that
/// process — crash collectors, profilers, monitoring agents and (on a debuggable
/// Android build) `adb` all see it — so passing the envelope key as
/// `AETHER_CONFIG_KEY` meant the key to every identity on disk sat in a
/// process-wide, long-lived, world-adjacent place. One line down the pipe this
/// parent already owns carries the same bytes with a far shorter exposure, and
/// the key is zeroized immediately after.
///
/// The driver path left the environment for the same reason and a sharper one:
/// `AETHER_WINTUN` was the elevated engine being told "load that DLL" by a value
/// any bystander able to influence the environment could set.
pub(crate) fn handoff_preamble(
    child: &mut Child,
    key: &str,
    wintun: Option<&Path>,
) -> Result<(), CommandError> {
    use std::io::Write as _;
    let Some(stdin) = child.stdin.as_mut() else {
        return Err(CommandError::new(
            "internal",
            "engine stdin is not piped; refusing to launch an engine that cannot receive its key",
        ));
    };
    let mut buf: Vec<u8> = Vec::with_capacity(key.len() + 64);
    buf.extend_from_slice(b"key ");
    buf.extend_from_slice(key.as_bytes());
    buf.push(b'\n');
    if let Some(path) = wintun {
        // Lossy-converted paths would name a file that does not exist, and the
        // engine would then refuse to start the tunnel with a confusing error.
        let text = path.to_str().ok_or_else(|| {
            CommandError::new(
                "handoff_failed",
                format!(
                    "wintun path {} is not valid UTF-8; install Aether under a plain path",
                    path.display()
                ),
            )
        })?;
        // Windows forbids control characters in file names, so a path cannot
        // forge a second preamble line.
        buf.extend_from_slice(b"dll wintun ");
        buf.extend_from_slice(text.as_bytes());
        buf.push(b'\n');
    }
    let written = stdin.write_all(&buf).and_then(|()| stdin.flush());
    zeroize::Zeroize::zeroize(&mut buf);
    match written {
        Ok(()) => Ok(()),
        Err(e) => Err(CommandError::new(
            "handoff_failed",
            format!("handoff write: {e}"),
        )),
    }
}

pub(crate) fn engine_path(app: &AppHandle, settings: &Settings) -> Result<PathBuf, CommandError> {
    // TUN: never honor custom overrides (elevated risk).
    // Non-TUN: custom paths allowed only after full trust checks.
    if settings.routing_mode != RoutingMode::Tun && !settings.engine_path.trim().is_empty() {
        let path = PathBuf::from(settings.engine_path.trim());
        if !path.exists() {
            return Err("Configured aether.exe was not found".into());
        }
        validate_trusted_binary(&path, "aether.exe")?;
        return Ok(path);
    }
    // No `AETHER_ENGINE` override: `settings.engine_path` above already lets a
    // user point at their own build, it is visible in the UI and persisted, and
    // it goes through the same `validate_trusted_binary` check. A second,
    // invisible env route to the same decision is how "which binary did the
    // shell actually launch" stops being answerable from the saved settings.
    if let Some(path) = resolve_resource(app, "aether.exe") {
        // Verified here, on every branch, rather than by each caller
        // remembering to: this function is the only way the shell learns which
        // binary to launch, and a returned path that skipped the checks turned
        // "we always validate the engine" into a claim about one call site.
        validate_trusted_binary(&path, "aether.exe")?;
        return Ok(path);
    }
    // Portable layout (Windows is case-insensitive: avoid "Aether.exe" vs "aether.exe")
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            for rel in [
                "engine\\aether.exe",
                "engine/aether.exe",
                "aether-engine.exe",
                "aether.exe",
            ] {
                let path = dir.join(rel);
                if path.exists() {
                    validate_trusted_binary(&path, "aether.exe")?;
                    return Ok(path);
                }
            }
        }
    }
    if settings.routing_mode == RoutingMode::Tun {
        return Err("aether.exe not found next to app; reinstall or use portable package".into());
    }
    let repo_build =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../aether/target/release/aether.exe");
    let Some(path) = repo_build.exists().then_some(repo_build) else {
        return Err(
            "aether.exe not found. Build engine or choose it in Settings > Advanced.".into(),
        );
    };
    // The repository-build fallback is a development convenience. `validate_trusted_binary`
    // tolerates an unsigned local build only in a debug binary (see
    // `allow_unsigned_for_dev`), so in a release build this path cannot be used
    // to launch an engine nobody signed.
    validate_trusted_binary(&path, "aether.exe")?;
    Ok(path)
}

pub(crate) fn wintun_path(app: &AppHandle) -> Option<PathBuf> {
    if let Some(path) = resolve_resource(app, "wintun.dll") {
        return Some(path);
    }
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("wintun.dll")))
        .filter(|p| p.exists())
}
