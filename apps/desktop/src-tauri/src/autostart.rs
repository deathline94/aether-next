//! The HKCU\\Run launch-at-login entry, including the `--minimized` flag the
//! shell's own startup path reads back.

use crate::CommandError;

use std::env;
use winreg::{enums::HKEY_CURRENT_USER, RegKey};

const VALUE: &str = "Aether Next";

pub fn set(enabled: bool) -> Result<(), CommandError> {
    let key = RegKey::predef(HKEY_CURRENT_USER)
        .open_subkey_with_flags(
            "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            winreg::enums::KEY_SET_VALUE | winreg::enums::KEY_QUERY_VALUE,
        )
        .map_err(CommandError::from)?;
    if enabled {
        let exe = env::current_exe().map_err(CommandError::from)?;
        // `--minimized`: the setting's own name promises a start that stays in
        // the tray, and `setup` only ever consulted settings.json — which the
        // shell being started *by* this key also has, but a launch-at-logon
        // with no window is what "Launch at login" has always meant here.
        let cmd = format!("\"{}\" --minimized", exe.display());
        key.set_value(VALUE, &cmd).map_err(CommandError::from)
    } else {
        // A failed delete used to be discarded and `Ok` returned, so the
        // "Launch at login" toggle could display *off* while HKCU\Run still
        // started the app at every logon. An absent value is the state that was
        // asked for; anything else is a write that did not happen.
        match key.delete_value(VALUE) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(CommandError::new(
                "autostart",
                format!("could not remove the `{VALUE}` Run entry: {e}"),
            )),
        }
    }
}
