//! Process hygiene for the elevated engine: where a name resolves to, and what
//! the loader is allowed to search.
//!
//! Two variants of the same defect. `Command::new("route")` and
//! `LoadLibrary("wintun.dll")` both fall back to the *standard search order*,
//! which includes the current directory and the directory holding the parent
//! executable's peers. For an ordinary process that is a nuisance; for the
//! process this app starts elevated to mutate the routing table it is a token
//! escalation with a file drop in it — anything that can place
//! `route.exe`/`icacls.exe`/`kernel32.dll` in a directory the engine happens to
//! be sitting in gets executed with administrator rights.
//!
//! So: resolve every spawned tool to its absolute `%WINDIR%\System32` path, and
//! pin the DLL search order to System32 for everything else.

use std::path::PathBuf;

use windows_sys::Win32::System::LibraryLoader::{
    SetDefaultDllDirectories, LOAD_LIBRARY_SEARCH_SYSTEM32,
};
use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;

use crate::error::{AetherError, Result};

fn system_dir() -> Result<PathBuf> {
    // 32767 is the maximum path length in wide characters; the call reports the
    // number of characters it wrote (excluding the NUL), or the size it needed.
    let mut buf = vec![0u16; 32_767];
    let needed = unsafe { GetSystemDirectoryW(buf.as_mut_ptr(), buf.len() as u32) };
    if needed == 0 {
        return Err(AetherError::HostState(format!(
            "GetSystemDirectoryW failed: {}",
            std::io::Error::last_os_error()
        )));
    }
    let n = usize::try_from(needed).map_err(|_| {
        AetherError::HostState("GetSystemDirectoryW returned an absurd length".into())
    })?;
    if n >= buf.len() {
        return Err(AetherError::HostState(format!(
            "system directory path needs {n} characters, more than the buffer"
        )));
    }
    Ok(PathBuf::from(String::from_utf16_lossy(&buf[..n])))
}

/// Absolute path to `%WINDIR%\System32\<name>.exe`.
///
/// `name` must be a bare tool name. A caller that passes `foo` gets
/// `C:\Windows\System32\foo.exe` or an error — never a search, and never
/// something relative to wherever the process happens to be.
pub fn system_exe(name: &str) -> Result<PathBuf> {
    let lowered = name.to_ascii_lowercase();
    if lowered.is_empty()
        || lowered.len() > 64
        || lowered.contains(['/', '\\', ':'])
        || !lowered
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
    {
        return Err(AetherError::HostState(format!(
            "{name:?} is not a bare tool name; refusing to resolve it through the search path"
        )));
    }
    let file = if lowered.ends_with(".exe") {
        lowered.clone()
    } else {
        format!("{lowered}.exe")
    };
    let sys = system_dir()?;
    if lowered == "powershell" || lowered == "powershell.exe" {
        let ps_path = sys
            .join("WindowsPowerShell")
            .join("v1.0")
            .join("powershell.exe");
        if ps_path.is_file() {
            return Ok(ps_path);
        }
    }
    let mut path = sys;
    path.push(file);
    if !path.is_file() {
        return Err(AetherError::HostState(format!(
            "{} does not exist; refusing to run {name} from anywhere else",
            path.display()
        )));
    }
    Ok(path)
}

/// Restrict the DLL search order for this process to `%WINDIR%\System32`.
///
/// Called before anything loads a library. Failing here is fatal on purpose: the
/// only known cause is a platform old enough to lack the API, and continuing with
/// the default order would mean the control silently does nothing.
pub fn pin_dll_search_path() -> Result<()> {
    if unsafe { SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32) } == 0 {
        return Err(AetherError::HostState(format!(
            "SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32) failed: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bare_tool_name_resolves_inside_system32() {
        let p = system_exe("icacls").expect("icacls exists on every supported Windows");
        assert!(p.to_string_lossy().ends_with("icacls.exe"));
        assert!(
            p.parent()
                .map(|d| d == system_dir().unwrap())
                .unwrap_or(false),
            "resolved outside the system directory: {}",
            p.display()
        );
    }

    #[test]
    fn powershell_resolves_to_system_powershell() {
        let p = system_exe("powershell").expect("powershell exists on every supported Windows");
        assert!(p
            .to_string_lossy()
            .to_ascii_lowercase()
            .ends_with("powershell.exe"));
        assert!(p.is_file());
        assert!(p.starts_with(system_dir().unwrap()));
    }

    #[test]
    fn anything_resembling_a_path_is_refused() {
        for bad in [
            "",
            "..\\evil",
            "C:\\tmp\\route",
            "a/b",
            "x".repeat(80).as_str(),
            "net;sh",
        ] {
            assert!(system_exe(bad).is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn a_missing_tool_is_an_error_not_a_fallback() {
        assert!(system_exe("definitely-not-a-windows-tool").is_err());
    }
}
