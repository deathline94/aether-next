//! Host access-control plumbing: absolute `%SystemRoot%\\System32` paths, the
//! caller's own token SID, and the DACL restriction applied to every file that
//! holds a secret.
use crate::error::CommandError;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Absolute path to a binary under `%SystemRoot%\\System32`.
///
/// `Command::new("icacls")` resolves through the standard Windows search order,
/// which tries the *application directory* first. The portable package ships the
/// GUI into a folder that `allowed_binary_roots` also trusts, so a dropped
/// `icacls.exe`/`powershell.exe` beside the exe runs with the shell's token: the
/// interactive user, and Administrator on the documented elevated TUN path.
/// System utilities are therefore always addressed by full path, and a missing
/// `%SystemRoot%` fails closed instead of falling back to the bare name.
#[cfg(windows)]
pub(crate) fn system32(program: &str) -> Result<PathBuf, CommandError> {
    let root = std::env::var_os("SystemRoot")
        .or_else(|| std::env::var_os("WINDIR"))
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .ok_or_else(|| {
            CommandError::new(
                "internal",
                format!("cannot locate %SystemRoot%\\System32\\{program}"),
            )
        })?;
    Ok(root.join("System32").join(program))
}

/// SDDL string (`S-1-5-21-...`) for the user SID of *this* process token.
///
/// Built from `GetTokenInformation(TokenUser)` rather than `ConvertSidToStringSidW`
/// so no ambient environment value takes part in an access decision.
#[cfg(windows)]
fn current_user_sid_string() -> Result<String, CommandError> {
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::Security::{
        GetLengthSid, GetSidSubAuthority, GetSidSubAuthorityCount, GetTokenInformation, IsValidSid,
        TokenUser, PSID, SID, TOKEN_QUERY, TOKEN_USER,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    unsafe {
        let mut token: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return Err(CommandError::new("internal", "cannot open process token"));
        }
        // First call fails with ERROR_INSUFFICIENT_BUFFER and reports the size.
        let mut needed = 0u32;
        GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut needed);
        if needed < std::mem::size_of::<TOKEN_USER>() as u32 {
            CloseHandle(token);
            return Err(CommandError::new("internal", "cannot read token user SID"));
        }
        let mut buf = vec![0u8; needed as usize];
        let ok = GetTokenInformation(
            token,
            TokenUser,
            buf.as_mut_ptr() as *mut _,
            needed,
            &mut needed,
        );
        CloseHandle(token);
        if ok == 0 {
            return Err(CommandError::new("internal", "cannot read token user SID"));
        }
        let user: TOKEN_USER = std::ptr::read_unaligned(buf.as_ptr() as *const TOKEN_USER);
        let sid: PSID = user.User.Sid;
        if sid.is_null() || IsValidSid(sid) == 0 || GetLengthSid(sid) == 0 {
            return Err(CommandError::new("internal", "malformed token user SID"));
        }
        let sid_ref = &*(sid as *const SID);
        let count_ptr = GetSidSubAuthorityCount(sid);
        if sid_ref.Revision != 1 || count_ptr.is_null() {
            return Err(CommandError::new("internal", "malformed token user SID"));
        }
        let mut identifier_authority: u64 = 0;
        for byte in sid_ref.IdentifierAuthority.Value.iter() {
            identifier_authority = (identifier_authority << 8) | u64::from(*byte);
        }
        let mut out = format!("S-{}-{}", sid_ref.Revision, identifier_authority);
        for index in 0..u32::from(*count_ptr) {
            let sub = GetSidSubAuthority(sid, index);
            if sub.is_null() {
                return Err(CommandError::new("internal", "malformed token user SID"));
            }
            out.push('-');
            out.push_str(&(*sub).to_string());
        }
        Ok(out)
    }
}

#[cfg(windows)]
pub fn restrict_directory_acl(path: &Path) -> Result<(), CommandError> {
    // Fail closed. The previous `if let Ok(user)` skipped the whole ACL whenever
    // the principal was unavailable, so the file that gates every other secret
    // kept whatever the directory handed out.
    //
    // The principal comes from the token's user SID, never from `%USERNAME%`: on
    // the documented elevated path ("Run as administrator" with a different
    // admin credential) the env var names the *elevator's* account, so one
    // elevated run re-granted the secrets to the admin and locked the ordinary
    // user out of settings.json / config_key.dpapi / aether.toml - and made the
    // DPAPI master key undecryptable for the account that owns it.
    let sid = current_user_sid_string()?;
    let icacls = system32("icacls.exe")?;
    {
        let is_dir = path.is_dir();
        let scope = if is_dir { "(OI)(CI)" } else { "" };
        let user_perm = format!("*{sid}:{scope}F");
        let sys_perm = format!("SYSTEM:{scope}F");
        let output = Command::new(&icacls)
            .arg(path.as_os_str())
            // Grant only. `/inheritance:r` revoked every inherited ACE, which is
            // how an elevated run could delete the owning user's inherited
            // access; `/grant:r` replaces just the explicit ACE for each named
            // principal and leaves inheritance (and the owner's grant coming
            // through it) untouched.
            .arg("/grant:r")
            .arg(&user_perm)
            .arg("/grant:r")
            .arg(sys_perm)
            .output()
            .map_err(|e| {
                format!(
                    "failed to execute {} on {}: {e}",
                    icacls.display(),
                    path.display()
                )
            })?;
        if !output.status.success() {
            let err = String::from_utf8_lossy(&output.stderr);
            return Err(format!(
                "icacls failed to restrict permissions on {}: {}",
                path.display(),
                err.trim()
            )
            .into());
        }
    }
    Ok(())
}

#[cfg(not(windows))]
pub fn restrict_directory_acl(_path: &Path) -> Result<(), CommandError> {
    Ok(())
}
