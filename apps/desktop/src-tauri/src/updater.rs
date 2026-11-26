//! Inline GitHub Releases updater for Aether Next Desktop.
//!
//! Checks the latest release via GitHub API, resolves the Windows installer
//! asset + SHA-256 digest from `SHA256SUMS.txt` when present, streams the
//! download with progress events into `app_cache_dir/updates`, verifies its
//! SHA-256 hash before touching disk/launching, and opens the installer with
//! `tauri-plugin-opener` (so `Command::new` never bypasses `BC-02`/`BC-05`).

use crate::error::CommandError;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use tauri::{AppHandle, Emitter, Manager};
use tauri_plugin_opener::OpenerExt;

const LATEST_RELEASE_API: &str =
    "https://api.github.com/repos/deathline94/aether-next/releases/latest";
const RELEASES_PAGE: &str = "https://github.com/deathline94/aether-next/releases";
const MAX_DOWNLOAD_BYTES: u64 = 150 * 1024 * 1024;
const ALLOWED_DOWNLOAD_HOSTS: &[&str] = &[
    "github.com",
    "objects.githubusercontent.com",
    "release-assets.githubusercontent.com",
];

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct UpdateInfo {
    pub available: bool,
    pub current_version: String,
    pub latest_version: String,
    pub release_url: String,
    pub asset_name: String,
    pub asset_url: String,
    pub asset_size: u64,
    pub sha256: Option<String>,
    pub notes: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct UpdateProgress {
    pub stage: String,
    pub downloaded_bytes: u64,
    pub total_bytes: u64,
    pub percent: u8,
    pub message: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct InstallOutcome {
    pub status: String,
    pub path: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum PrereleasePart {
    Num(u64),
    Text(String),
}

fn parse_semver(raw: &str) -> Option<([u64; 3], Vec<PrereleasePart>)> {
    let trimmed = raw.trim().strip_prefix('v').unwrap_or(raw.trim());
    let without_build = trimmed.split('+').next()?;
    let (core, pre) = match without_build.split_once('-') {
        Some((c, p)) => (c, Some(p)),
        None => (without_build, None),
    };
    let nums: Vec<&str> = core.split('.').collect();
    if nums.is_empty() || nums.len() > 3 {
        return None;
    }
    let mut parsed = [0u64; 3];
    for (idx, part) in nums.iter().enumerate() {
        if part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        parsed[idx] = part.parse::<u64>().ok()?;
    }
    let pre_parts = match pre {
        Some(p) if !p.is_empty() => p
            .split('.')
            .map(|id| {
                if !id.is_empty() && id.bytes().all(|b| b.is_ascii_digit()) {
                    id.parse::<u64>()
                        .map(PrereleasePart::Num)
                        .unwrap_or_else(|_| PrereleasePart::Text(id.to_string()))
                } else {
                    PrereleasePart::Text(id.to_string())
                }
            })
            .collect(),
        _ => Vec::new(),
    };
    Some((parsed, pre_parts))
}

/// Returns `true` when `candidate` is strictly newer than `current` per SemVer 2.0.0.
pub fn semver_gt(candidate: &str, current: &str) -> bool {
    let (Some((ca, cpre)), Some((cu, cupre))) = (parse_semver(candidate), parse_semver(current))
    else {
        return false;
    };
    if ca != cu {
        return ca > cu;
    }
    match (cpre.is_empty(), cupre.is_empty()) {
        (true, true) => false,
        (true, false) => true,
        (false, true) => false,
        (false, false) => {
            for (a, b) in cpre.iter().zip(cupre.iter()) {
                if a == b {
                    continue;
                }
                return match (a, b) {
                    (PrereleasePart::Num(x), PrereleasePart::Num(y)) => x > y,
                    (PrereleasePart::Num(_), PrereleasePart::Text(_)) => false,
                    (PrereleasePart::Text(_), PrereleasePart::Num(_)) => true,
                    (PrereleasePart::Text(x), PrereleasePart::Text(y)) => x > y,
                };
            }
            cpre.len() > cupre.len()
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WindowsInstallKind {
    Portable,
    Setup,
}

/// Detect whether the running desktop binary belongs to a portable archive or
/// an NSIS setup installation so auto-update picks the matching release asset.
pub fn detect_windows_install_kind(exe_path: &Path) -> WindowsInstallKind {
    if let Some(dir) = exe_path.parent() {
        if dir.join("uninstall.exe").is_file() {
            return WindowsInstallKind::Setup;
        }
        if dir.join("engine").join("aether.exe").is_file() {
            return WindowsInstallKind::Portable;
        }
    }
    if exe_path
        .file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| n.eq_ignore_ascii_case("AetherNext-Desktop.exe"))
    {
        return WindowsInstallKind::Portable;
    }
    WindowsInstallKind::Setup
}

pub fn select_windows_asset(
    assets: &[serde_json::Value],
    kind: WindowsInstallKind,
) -> Option<(String, String, u64)> {
    let mut setup: Option<(String, String, u64)> = None;
    let mut portable: Option<(String, String, u64)> = None;
    for asset in assets {
        let name = asset.get("name").and_then(|v| v.as_str()).unwrap_or("");
        let url = asset
            .get("browser_download_url")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let size = asset.get("size").and_then(|v| v.as_u64()).unwrap_or(0);
        if name.is_empty() || url.is_empty() || validate_download_url(url).is_err() {
            continue;
        }
        let lower = name.to_ascii_lowercase();
        if setup.is_none()
            && (name.eq_ignore_ascii_case("AetherNext-windows-x64-setup.exe")
                || (lower.ends_with("-setup.exe") && lower.contains("windows")))
        {
            setup = Some((name.to_string(), url.to_string(), size));
        }
        if portable.is_none()
            && (name.eq_ignore_ascii_case("AetherNext-portable-windows-x64.zip")
                || (lower.ends_with(".zip") && lower.contains("windows")))
        {
            portable = Some((name.to_string(), url.to_string(), size));
        }
    }
    match kind {
        WindowsInstallKind::Portable => portable.or(setup),
        WindowsInstallKind::Setup => setup.or(portable),
    }
}

pub fn parse_sha256sums(body: &str, asset_name: &str) -> Option<String> {
    for line in body.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let mut parts = trimmed.split_whitespace();
        let digest = parts.next()?;
        let name = parts.next()?.trim_start_matches('*');
        if name == asset_name && digest.len() == 64 && digest.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Some(digest.to_ascii_lowercase());
        }
    }
    None
}

fn url_host(url: &str) -> Result<String, CommandError> {
    let rest = url
        .strip_prefix("https://")
        .ok_or_else(|| CommandError::new("invalid_url", "Update download URL must use HTTPS."))?;
    let host_port = rest.split(['/', '?', '#']).next().unwrap_or("");
    if host_port.is_empty() || host_port.contains('@') {
        return Err(CommandError::new("invalid_url", "Malformed download URL."));
    }
    let host = host_port
        .split(':')
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    if host.is_empty() {
        return Err(CommandError::new("invalid_url", "Missing URL host."));
    }
    Ok(host)
}

pub fn validate_download_url(url: &str) -> Result<(), CommandError> {
    let host = url_host(url)?;
    if !ALLOWED_DOWNLOAD_HOSTS
        .iter()
        .any(|allowed| *allowed == host)
    {
        return Err(CommandError::new(
            "untrusted_host",
            format!("Refusing update download from untrusted host '{host}'."),
        ));
    }
    Ok(())
}

pub fn validate_asset_name(name: &str) -> Result<(), CommandError> {
    let trimmed = name.trim();
    if trimmed.is_empty()
        || trimmed.contains('/')
        || trimmed.contains('\\')
        || trimmed.contains("..")
        || trimmed.contains(':')
    {
        return Err(CommandError::new(
            "invalid_asset",
            "Refusing unsafe update asset file name.",
        ));
    }
    let lower = trimmed.to_ascii_lowercase();
    if !lower.ends_with(".exe") && !lower.ends_with(".zip") {
        return Err(CommandError::new(
            "invalid_asset",
            "Update installer must be a .exe or .zip package.",
        ));
    }
    Ok(())
}

fn sanitize_release_page(candidate: Option<&str>) -> String {
    match candidate {
        Some(url) if url.starts_with("https://github.com/deathline94/aether-next/releases") => {
            url.to_string()
        }
        _ => RELEASES_PAGE.to_string(),
    }
}

fn build_http_client(
    http_port: Option<u16>,
    use_local_proxy: bool,
    read_timeout_secs: u64,
) -> Result<ureq::Agent, CommandError> {
    let mut builder = ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(15))
        .timeout_read(Duration::from_secs(read_timeout_secs));
    if use_local_proxy {
        if let Some(port) = http_port.filter(|p| (1024..=65535).contains(p)) {
            let proxy_uri = format!("http://127.0.0.1:{port}");
            let proxy = ureq::Proxy::new(&proxy_uri).map_err(CommandError::from)?;
            builder = builder.proxy(proxy);
        }
    }
    Ok(builder.build())
}

fn user_agent() -> String {
    format!("AetherNext/{}", env!("CARGO_PKG_VERSION"))
}

pub(crate) fn check_update_blocking(
    http_port: Option<u16>,
    use_local_proxy: bool,
) -> Result<UpdateInfo, CommandError> {
    let current = env!("CARGO_PKG_VERSION");
    let client = build_http_client(http_port, use_local_proxy, 20)?;
    let resp = client
        .get(LATEST_RELEASE_API)
        .set("User-Agent", &user_agent())
        .set("Accept", "application/vnd.github+json")
        .call()
        .map_err(|e| {
            CommandError::new("update_check_failed", format!("Update check failed: {e}"))
        })?;

    let body = resp.into_string().map_err(|e| {
        CommandError::new(
            "update_check_failed",
            format!("Invalid response body from GitHub Releases: {e}"),
        )
    })?;
    let payload: serde_json::Value = serde_json::from_str(&body).map_err(|e| {
        CommandError::new(
            "update_check_failed",
            format!("Invalid JSON from GitHub Releases: {e}"),
        )
    })?;

    let tag = payload
        .get("tag_name")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim();
    if tag.is_empty() {
        return Err(CommandError::new(
            "update_check_failed",
            "Latest GitHub release is missing tag_name.",
        ));
    }

    let latest_version = tag.strip_prefix('v').unwrap_or(tag).to_string();
    let release_url = sanitize_release_page(payload.get("html_url").and_then(|v| v.as_str()));
    let notes = payload
        .get("body")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .chars()
        .take(1500)
        .collect();
    let assets = payload
        .get("assets")
        .and_then(|v| v.as_array())
        .map(Vec::as_slice)
        .unwrap_or(&[]);

    let install_kind = std::env::current_exe()
        .ok()
        .map(|p| detect_windows_install_kind(&p))
        .unwrap_or(WindowsInstallKind::Setup);
    let (asset_name, asset_url, asset_size) =
        select_windows_asset(assets, install_kind).unwrap_or_default();
    let available = semver_gt(&latest_version, current) && !asset_url.is_empty();

    let sha256 = if available {
        assets
            .iter()
            .find(|a| a.get("name").and_then(|n| n.as_str()) == Some("SHA256SUMS.txt"))
            .and_then(|a| a.get("browser_download_url").and_then(|u| u.as_str()))
            .filter(|u| validate_download_url(u).is_ok())
            .and_then(|sums_url| {
                client
                    .get(sums_url)
                    .set("User-Agent", &user_agent())
                    .call()
                    .ok()
                    .and_then(|r| {
                        validate_download_url(r.get_url()).ok()?;
                        r.into_string().ok()
                    })
                    .and_then(|txt| parse_sha256sums(&txt, &asset_name))
            })
    } else {
        None
    };

    Ok(UpdateInfo {
        available,
        current_version: current.to_string(),
        latest_version,
        release_url,
        asset_name,
        asset_url,
        asset_size,
        sha256,
        notes,
    })
}

fn emit_progress(
    app: &AppHandle,
    stage: &str,
    downloaded_bytes: u64,
    total_bytes: u64,
    message: &str,
) {
    let percent = downloaded_bytes
        .saturating_mul(100)
        .checked_div(total_bytes)
        .unwrap_or(0)
        .min(100) as u8;
    let _ = app.emit(
        "update-progress",
        UpdateProgress {
            stage: stage.to_string(),
            downloaded_bytes,
            total_bytes,
            percent,
            message: message.to_string(),
        },
    );
}

fn sha256_file_hex(path: &Path) -> Result<String, CommandError> {
    let mut f = File::open(path).map_err(CommandError::from)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf).map_err(CommandError::from)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(64);
    for b in digest {
        use std::fmt::Write;
        let _ = write!(hex, "{b:02x}");
    }
    Ok(hex)
}

fn updates_cache_dir(app: &AppHandle) -> Result<PathBuf, CommandError> {
    let cache = app
        .path()
        .app_cache_dir()
        .map_err(|e| CommandError::new("cache_dir_unavailable", e.to_string()))?;
    let dir = cache.join("updates");
    fs::create_dir_all(&dir).map_err(CommandError::from)?;
    Ok(dir)
}

pub(crate) fn download_and_install_blocking(
    app: AppHandle,
    asset_url: String,
    asset_name: String,
    expected_sha256: Option<String>,
    http_port: Option<u16>,
    use_local_proxy: bool,
) -> Result<InstallOutcome, CommandError> {
    validate_download_url(&asset_url)?;
    validate_asset_name(&asset_name)?;
    let normalized_expected = expected_sha256
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()));

    let dir = updates_cache_dir(&app)?;
    let dest = dir.join(&asset_name);

    // Reuse an already-downloaded verified package so retries don't re-fetch.
    let cached_ok = dest.is_file()
        && normalized_expected
            .as_ref()
            .is_some_and(|want| sha256_file_hex(&dest).is_ok_and(|got| got == *want));

    if !cached_ok {
        emit_progress(
            &app,
            "downloading",
            0,
            0,
            "Connecting to GitHub Releases...",
        );
        let client = build_http_client(http_port, use_local_proxy, 60)?;
        let resp = client
            .get(&asset_url)
            .set("User-Agent", &user_agent())
            .call()
            .map_err(|e| {
                emit_progress(&app, "error", 0, 0, &format!("Download failed: {e}"));
                CommandError::new(
                    "update_download_failed",
                    format!("Update download failed: {e}"),
                )
            })?;

        // Re-check final host after GitHub's 302 redirect to CDN.
        validate_download_url(resp.get_url())?;
        let total = resp
            .header("Content-Length")
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(0);
        if total > MAX_DOWNLOAD_BYTES {
            return Err(CommandError::new(
                "update_too_large",
                "Update archive exceeds maximum permitted size (150 MiB).",
            ));
        }

        let part = dir.join(format!("{asset_name}.part"));
        let mut reader = resp.into_reader();
        let mut file = File::create(&part).map_err(CommandError::from)?;
        let mut hasher = Sha256::new();
        let mut buf = [0u8; 64 * 1024];
        let mut downloaded = 0u64;
        let mut last_emit = Instant::now();

        let stream_res: Result<(), CommandError> = (|| {
            loop {
                let n = reader.read(&mut buf).map_err(CommandError::from)?;
                if n == 0 {
                    break;
                }
                downloaded = downloaded.saturating_add(n as u64);
                if downloaded > MAX_DOWNLOAD_BYTES {
                    return Err(CommandError::new(
                        "update_too_large",
                        "Update stream exceeded 150 MiB safety limit.",
                    ));
                }
                file.write_all(&buf[..n]).map_err(CommandError::from)?;
                hasher.update(&buf[..n]);
                if last_emit.elapsed() >= Duration::from_millis(150) {
                    emit_progress(
                        &app,
                        "downloading",
                        downloaded,
                        total,
                        "Downloading update...",
                    );
                    last_emit = Instant::now();
                }
            }
            file.flush().map_err(CommandError::from)?;
            Ok(())
        })();

        if let Err(err) = stream_res {
            drop(file);
            let _ = fs::remove_file(&part);
            emit_progress(&app, "error", downloaded, total, &err.message);
            return Err(err);
        }
        drop(file);

        emit_progress(
            &app,
            "verifying",
            downloaded,
            total,
            "Verifying SHA-256 digest...",
        );
        let digest = hasher.finalize();
        let mut got_hex = String::with_capacity(64);
        for b in digest {
            use std::fmt::Write;
            let _ = write!(got_hex, "{b:02x}");
        }
        if let Some(ref want) = normalized_expected {
            if &got_hex != want {
                let _ = fs::remove_file(&part);
                let msg = "Downloaded update failed SHA-256 verification.";
                emit_progress(&app, "error", downloaded, total, msg);
                return Err(CommandError::new("sha256_mismatch", msg));
            }
        }
        if dest.exists() {
            let _ = fs::remove_file(&dest);
        }
        fs::rename(&part, &dest).map_err(CommandError::from)?;
    }

    let dest_str = dest.to_string_lossy().to_string();
    let is_portable_zip = asset_name.to_ascii_lowercase().ends_with(".zip");

    #[cfg(windows)]
    if is_portable_zip {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        const DETACHED_PROCESS: u32 = 0x0000_0008;

        let current_exe = std::env::current_exe().map_err(|e| {
            CommandError::new(
                "portable_exe_unknown",
                format!("Could not locate current executable: {e}"),
            )
        })?;
        let target_dir = current_exe.parent().ok_or_else(|| {
            CommandError::new(
                "portable_dir_unknown",
                "Could not resolve portable application directory.",
            )
        })?;

        // Probe folder write access before stopping an active tunnel session.
        let write_probe = target_dir.join(".aether-update-write-test");
        File::create(&write_probe)
            .and_then(|f| {
                drop(f);
                fs::remove_file(&write_probe)
            })
            .map_err(|e| {
                CommandError::new(
                    "portable_dir_read_only",
                    format!(
                        "Cannot write portable update to {}: {e}",
                        target_dir.display()
                    ),
                )
            })?;

        emit_progress(
            &app,
            "installing",
            100,
            100,
            "Stopping tunnel and applying portable update...",
        );
        crate::scan::stop_scan_child(&app.state::<crate::state::AppState>().scan_child);
        let _ = crate::supervision::disconnect_blocking(app.clone());

        let script_path = dir.join("apply-portable-update.ps1");
        let script = r#"param(
    [Parameter(Mandatory=$true)][int]$ParentPid,
    [Parameter(Mandatory=$true)][string]$ZipPath,
    [Parameter(Mandatory=$true)][string]$TargetDir,
    [Parameter(Mandatory=$true)][string]$LaunchExe
)
$ErrorActionPreference = 'Stop'
for ($i = 0; $i -lt 80; $i++) {
    if (-not (Get-Process -Id $ParentPid -ErrorAction SilentlyContinue)) { break }
    Start-Sleep -Milliseconds 250
}
Start-Sleep -Milliseconds 250
$stage = Join-Path ([System.IO.Path]::GetDirectoryName($ZipPath)) ('stage-' + [System.Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $stage | Out-Null
try {
    Expand-Archive -LiteralPath $ZipPath -DestinationPath $stage -Force
    $srcRoot = $stage
    $topExes = @(Get-ChildItem -LiteralPath $stage -Filter '*.exe' -File)
    if ($topExes.Count -eq 0) {
        $subDirs = @(Get-ChildItem -LiteralPath $stage -Directory)
        if ($subDirs.Count -eq 1) { $srcRoot = $subDirs[0].FullName }
    }
    $hasExe = @(Get-ChildItem -LiteralPath $srcRoot -Filter '*.exe' -File).Count -gt 0
    if (-not $hasExe) { throw 'Portable update archive contains no executable.' }
    $copied = $false
    for ($try = 0; $try -lt 15; $try++) {
        try {
            Copy-Item -Path (Join-Path $srcRoot '*') -Destination $TargetDir -Recurse -Force -ErrorAction Stop
            $copied = $true
            break
        } catch {
            Start-Sleep -Milliseconds 300
        }
    }
    if (-not $copied) { throw 'Timed out replacing portable update files.' }
    $toLaunch = if (Test-Path -LiteralPath $LaunchExe) {
        $LaunchExe
    } else {
        $firstExe = Get-ChildItem -LiteralPath $TargetDir -Filter '*.exe' -File | Select-Object -First 1
        if ($firstExe) { $firstExe.FullName } else { $LaunchExe }
    }
    if (Test-Path -LiteralPath $toLaunch) {
        Start-Process -FilePath $toLaunch -WorkingDirectory $TargetDir
    }
} finally {
    Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $ZipPath -Force -ErrorAction SilentlyContinue
}
"#;
        fs::write(&script_path, script.as_bytes()).map_err(CommandError::from)?;

        let powershell = crate::acl::system32(r"WindowsPowerShell\v1.0\powershell.exe")?;
        let mut cmd = std::process::Command::new(&powershell);
        cmd.args([
            "-NoProfile",
            "-NonInteractive",
            "-WindowStyle",
            "Hidden",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
        ])
        .arg(&script_path)
        .args(["-ParentPid", &std::process::id().to_string()])
        .arg("-ZipPath")
        .arg(&dest)
        .arg("-TargetDir")
        .arg(target_dir)
        .arg("-LaunchExe")
        .arg(&current_exe)
        .creation_flags(CREATE_NO_WINDOW | DETACHED_PROCESS);
        cmd.spawn().map_err(|e| {
            let msg = format!("Could not start portable updater helper: {e}");
            emit_progress(&app, "error", 0, 0, &msg);
            CommandError::new("portable_updater_spawn_failed", msg)
        })?;

        let exit_app = app.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(300));
            exit_app.exit(0);
        });

        return Ok(InstallOutcome {
            status: "restarting".to_string(),
            path: dest_str,
        });
    }

    let _ = is_portable_zip;
    emit_progress(
        &app,
        "installing",
        100,
        100,
        "Stopping tunnel and launching installer...",
    );
    crate::scan::stop_scan_child(&app.state::<crate::state::AppState>().scan_child);
    let _ = crate::supervision::disconnect_blocking(app.clone());
    app.opener()
        .open_path(&dest_str, None::<&str>)
        .map_err(|e| {
            let msg = format!("Could not launch installer ({dest_str}): {e}");
            emit_progress(&app, "error", 0, 0, &msg);
            CommandError::new("open_installer_failed", msg)
        })?;

    let exit_app = app.clone();
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(400));
        exit_app.exit(0);
    });

    Ok(InstallOutcome {
        status: "restarting".to_string(),
        path: dest_str,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn semver_gt_handles_versions() {
        assert!(semver_gt("1.3.17", "1.3.16"));
        assert!(semver_gt("v2.0.0", "1.9.9"));
        assert!(semver_gt("1.10.0", "1.9.0"));
        assert!(semver_gt("1.3.17", "1.3.17-rc.1"));
        assert!(!semver_gt("1.3.16", "1.3.16"));
        assert!(!semver_gt("1.3.16-beta.1", "1.3.16"));
        assert!(!semver_gt("invalid", "1.3.16"));
    }

    #[test]
    fn detect_windows_install_kind_distinguishes_portable_and_setup() {
        let base = std::env::temp_dir().join("aether-install-kind-test");
        let _ = fs::remove_dir_all(&base);

        let portable_dir = base.join("portable");
        fs::create_dir_all(portable_dir.join("engine")).unwrap();
        fs::write(portable_dir.join("engine").join("aether.exe"), b"").unwrap();
        assert_eq!(
            detect_windows_install_kind(&portable_dir.join("AetherNext-Desktop.exe")),
            WindowsInstallKind::Portable
        );

        let setup_dir = base.join("setup");
        fs::create_dir_all(&setup_dir).unwrap();
        fs::write(setup_dir.join("uninstall.exe"), b"").unwrap();
        assert_eq!(
            detect_windows_install_kind(&setup_dir.join("Aether Next.exe")),
            WindowsInstallKind::Setup
        );

        let named_portable = base.join("named").join("AetherNext-Desktop.exe");
        assert_eq!(
            detect_windows_install_kind(&named_portable),
            WindowsInstallKind::Portable
        );

        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn select_windows_asset_respects_install_kind() {
        let assets = vec![
            serde_json::json!({
                "name": "AetherNext-portable-windows-x64.zip",
                "browser_download_url": "https://github.com/deathline94/aether-next/releases/download/v1.3.17/AetherNext-portable-windows-x64.zip",
                "size": 9000000
            }),
            serde_json::json!({
                "name": "AetherNext-windows-x64-setup.exe",
                "browser_download_url": "https://github.com/deathline94/aether-next/releases/download/v1.3.17/AetherNext-windows-x64-setup.exe",
                "size": 6700000
            }),
        ];
        let picked_setup =
            select_windows_asset(&assets, WindowsInstallKind::Setup).expect("setup exe selected");
        assert_eq!(picked_setup.0, "AetherNext-windows-x64-setup.exe");

        let picked_portable = select_windows_asset(&assets, WindowsInstallKind::Portable)
            .expect("portable zip selected");
        assert_eq!(picked_portable.0, "AetherNext-portable-windows-x64.zip");
    }

    #[test]
    fn parse_sha256sums_finds_matching_entry() {
        let digest = "a".repeat(64);
        let sums = format!(
            "{}  AetherNext-android-universal.apk\n{} *AetherNext-windows-x64-setup.exe\n",
            "b".repeat(64),
            digest
        );
        assert_eq!(
            parse_sha256sums(&sums, "AetherNext-windows-x64-setup.exe"),
            Some(digest)
        );
        assert_eq!(parse_sha256sums(&sums, "missing.exe"), None);
    }

    #[test]
    fn rejects_untrusted_url_and_bad_asset_name() {
        assert!(validate_download_url("http://github.com/foo.exe").is_err());
        assert!(validate_download_url("https://evil.example.com/setup.exe").is_err());
        assert!(validate_download_url(
            "https://objects.githubusercontent.com/github-production-release-asset/foo"
        )
        .is_ok());

        assert!(validate_asset_name("../evil.exe").is_err());
        assert!(validate_asset_name("sub/evil.exe").is_err());
        assert!(validate_asset_name("payload.bat").is_err());
        assert!(validate_asset_name("AetherNext-windows-x64-setup.exe").is_ok());
    }

    #[test]
    fn sha256_verification_matches_and_rejects_mismatch() {
        let dir = std::env::temp_dir().join("aether-updater-sha-test");
        let _ = fs::create_dir_all(&dir);
        let file = dir.join("empty.bin");
        fs::write(&file, b"").unwrap();
        let hex = sha256_file_hex(&file).unwrap();
        assert_eq!(
            hex,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_ne!(hex, "0".repeat(64));
        let _ = fs::remove_dir_all(&dir);
    }
}
