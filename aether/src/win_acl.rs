//! The security identifier of the user this process actually runs as.
//!
//! File ACLs used to be granted to `%USERNAME%`. That name is not a principal:
//! an **elevated** engine process resolves it to the same display string while
//! its token is the Administrator account, so the ACL that came out of
//! `icacls … /grant {USERNAME}:F` let the elevated user in and locked the
//! ordinary user — the next normal launch could not read its own config and
//! re-provisioned a second WARP device. A SID cannot be ambiguous about which
//! account it names, and it is derived from the token that will open the file.
//!
//! What the ACL itself is: `config.rs` applies `/inheritance:r /grant:r
//! *<sid>:F` through `icacls`, i.e. one explicit grant to the token's own
//! account and nothing inherited. This module used to also build
//! `D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGWX;<sid>)` and never apply it - no
//! `ConvertStringSecurityDescriptorToSecurityDescriptorW` call existed anywhere.
//! The difference is not cosmetic and the shipped form is the tighter one: the
//! envelope is only decryptable by this user's DPAPI master key anyway, so
//! handing `GA` to SYSTEM and the Administrators group widened *who can read the
//! ciphertext* without widening who can read the plaintext. The spec's older
//! wording is corrected alongside this, not the code.

use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, LocalFree, HANDLE};
use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows_sys::Win32::Security::{GetTokenInformation, TokenUser, TOKEN_QUERY, TOKEN_USER};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

use crate::error::{AetherError, Result};

/// `S-1-5-21-…` for the current process token.
pub fn current_user_sid() -> Result<String> {
    unsafe {
        let mut token: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return Err(AetherError::HostState(format!(
                "OpenProcessToken failed: {}",
                std::io::Error::last_os_error()
            )));
        }

        // Ask for the size first; a fixed buffer would truncate a token with a
        // long attribute list and yield a garbage (or absent) SID.
        let mut needed: u32 = 0;
        GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut needed);
        if needed == 0 {
            let err = std::io::Error::last_os_error();
            CloseHandle(token);
            return Err(AetherError::HostState(format!(
                "GetTokenInformation size: {err}"
            )));
        }

        let mut buf: Vec<u8> = vec![0u8; needed as usize];
        let ok = GetTokenInformation(
            token,
            TokenUser,
            buf.as_mut_ptr() as *mut core::ffi::c_void,
            needed,
            &mut needed,
        );
        CloseHandle(token);
        if ok == 0 {
            return Err(AetherError::HostState(format!(
                "GetTokenInformation(TokenUser) failed: {}",
                std::io::Error::last_os_error()
            )));
        }

        let tu = &*(buf.as_ptr() as *const TOKEN_USER);
        let sid = tu.User.Sid;
        if sid.is_null() {
            return Err(AetherError::HostState("token has no user SID".into()));
        }

        let mut str_sid: *mut u16 = std::ptr::null_mut();
        if ConvertSidToStringSidW(sid, &mut str_sid) == 0 {
            return Err(AetherError::HostState(format!(
                "ConvertSidToStringSidW failed: {}",
                std::io::Error::last_os_error()
            )));
        }
        // `GetLastError` may still report ERROR_SUCCESS from an earlier call; the
        // non-zero return above is what proves the conversion.
        let _ = GetLastError();
        let mut len = 0usize;
        while *str_sid.add(len) != 0 {
            len += 1;
        }
        let wide = std::slice::from_raw_parts(str_sid, len);
        let out = String::from_utf16_lossy(wide);
        LocalFree(str_sid as *mut core::ffi::c_void);
        if !out.starts_with("S-1-") {
            return Err(AetherError::HostState(format!(
                "unexpected SID form {out:?} for the current token"
            )));
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The principal must come from the token, never from a display name.
    #[test]
    fn sid_is_a_sid_and_not_the_user_name() {
        let sid = current_user_sid().expect("token SID");
        assert!(sid.starts_with("S-1-"), "{sid} is not a SID");
        assert!(!sid.contains(' '), "SID must not contain spaces");
        assert!(sid.len() > 10, "{sid} looks truncated");
    }
}
