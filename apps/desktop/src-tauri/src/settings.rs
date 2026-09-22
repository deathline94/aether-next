//! The persisted configuration: the `wire_enum!` vocabulary, the shape of
//! `settings.json`, its validation, and the atomic on-disk read/write pair.
use crate::acl::restrict_directory_acl;
use crate::error::CommandError;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use tauri::{AppHandle, Manager};

#[cfg(windows)]
use crate::autostart;

/// A settings value drawn from a fixed vocabulary, with the wire format pinned.
///
/// Each of these used to be a `String` plus an allow-list in `validate_settings`,
/// which is the worst of both: the list could hold a typo (`"thorogh"`) as a legal
/// value, and it could disagree with what the UI offers — `ipVersion` accepted
/// `v4/v6/ipv4/dual…` but *not* `"both"`, the exact string the Scanner's
/// Dual-Stack option and the Settings row both send. The consequence was visible:
/// a legitimate choice was rejected on save and hard-broke the Connect button
/// while the identical label worked everywhere else.
///
/// Serialising always writes the canonical spelling, so the JSON on disk and in
/// the IPC payloads is byte-for-byte what the React app already produces — no
/// frontend change is needed. Deserialising accepts that spelling plus the legacy
/// aliases that meant the same thing, and a value the vocabulary cannot name
/// falls back to the variant `Settings::default()` would have produced rather
/// than turning a stale config into a load error (a *non-string* is still a type
/// error; `#[serde(default)]` is for absent keys, not for garbage).
macro_rules! wire_enum {
    (
        $(#[$meta:meta])*
        enum $name:ident {
            $($variant:ident = $wire:literal $(| $alias:literal)* $(,)?)*
        }
        default $default:ident
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum $name {
            $($variant),*
        }

        impl $name {
            /// The one spelling on the wire and in the child's environment.
            pub fn as_str(&self) -> &'static str {
                match self { $( $name::$variant => $wire, )* }
            }

            /// Canonical spelling plus the aliases that have always meant it.
            pub fn parse(raw: &str) -> Option<Self> {
                let value = raw.trim().to_ascii_lowercase();
                $(
                    if value == $wire $(|| value == $alias)* {
                        return Some($name::$variant);
                    }
                )*
                None
            }

            /// Every value the type can hold, for error prose.
            pub const ALL: &'static [$name] = &[$( $name::$variant ),*];
        }

        impl Default for $name {
            fn default() -> Self {
                $name::$default
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(self.as_str())
            }
        }

        impl serde::Serialize for $name {
            fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                s.serialize_str(self.as_str())
            }
        }

        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                let raw = <String as serde::Deserialize>::deserialize(d)?;
                let value = Self::parse(&raw).unwrap_or_default();
                if Self::parse(&raw).is_none() && !raw.trim().is_empty() {
                    eprintln!(
                        "settings: {raw:?} is not a {} and was read as {:?}",
                        stringify!($name),
                        value,
                    );
                }
                Ok(value)
            }
        }
    };
}

wire_enum! {
    /// Tunnel protocol the engine dials. `warp` is legacy but a shipped config can
    /// hold it, so it stays representable rather than silently becoming `masque`.
    enum Protocol {
        Masque = "masque",
        Wireguard = "wireguard",
        Warp = "warp",
        Gool = "gool",
    }
    default Masque
}

wire_enum! {
    /// MASQUE inner transport. `auto` is the legacy "let the engine choose" value;
    /// it is not the same statement as `h3`, so it keeps its own variant.
    enum TransportKind {
        H3 = "h3",
        H2 = "h2",
        Auto = "auto",
    }
    default H2
}

wire_enum! {
    /// Probe velocity profile — "Probe Velocity Profile" in the Settings UI.
    ///
    /// The set is the engine's (`turbo/balanced/thorough/stealth/ironclad`), not
    /// the allow-list's, which also carried `fast`/`deep` as aliases, `auto` as a
    /// non-value and `"thorogh"` as a typo. Aliases below are the ones with a
    /// single established meaning; a misspelling is not an alias of anything.
    enum ScanMode {
        Turbo = "turbo" | "fast",
        Balanced = "balanced" | "auto",
        Thorough = "thorough" | "deep",
        Stealth = "stealth" | "quiet",
        Ironclad = "ironclad" | "verify",
    }
    default Balanced
}

wire_enum! {
    /// Address families to probe. `Dual` is the wire value `"both"` the UI has
    /// always sent — `"dual"` and `"all"` are the engine's aliases for it.
    enum IpVersion {
        Auto = "auto",
        V4 = "v4" | "4" | "ipv4",
        V6 = "v6" | "6" | "ipv6",
        Dual = "both" | "dual" | "all",
    }
    default V4
}

wire_enum! {
    /// How the OS is pointed at the engine.
    enum RoutingMode {
        ProxyOnly = "proxy-only" | "proxy" | "none",
        SystemProxy = "system-proxy" | "system",
        Tun = "tun" | "wintun",
    }
    default SystemProxy
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
// A config written before a field existed must load with that field at its
// default. Without this, one missing key failed the whole file: the shell reported
// a hydration error, the UI ran on defaults, and the first save overwrote the
// user's protocol, ports and obfuscation choices. Invalid values are still errors;
// this covers absent keys only.
#[serde(default)]
pub struct Settings {
    pub protocol: Protocol,
    pub transport: TransportKind,
    pub scan_mode: ScanMode,
    pub ip_version: IpVersion,
    pub noize: String,
    /// Custom obfuscation: junk packet count (when noize == custom).
    pub noize_jc: u32,
    /// Custom obfuscation: min junk size.
    pub noize_jmin: u32,
    /// Custom obfuscation: max junk size.
    pub noize_jmax: u32,
    /// Custom obfuscation: interval between junk packets (ms).
    pub noize_interval_ms: u32,
    pub routing_mode: RoutingMode,
    pub socks_port: u16,
    pub http_port: u16,
    pub start_minimized: bool,
    pub launch_at_login: bool,
    pub engine_path: String,
    /// Forced peer endpoint (set by Scanner "Connect Direct").
    #[serde(default)]
    pub peer: String,
    /// H3 anti-DPI: split the QUIC Initial ClientHello across two datagrams so
    /// on-path DPI can't read the SNI from the first Initial packet.
    #[serde(default)]
    pub quic_initial_frag: bool,
    /// H3 anti-DPI: bytes of ClientHello CRYPTO carried in the first Initial.
    #[serde(default = "default_quic_frag_size")]
    pub quic_initial_frag_size: u32,
}

fn default_quic_frag_size() -> u32 {
    96
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            protocol: Protocol::Masque,
            transport: TransportKind::H2,
            // Prefer balanced over turbo: better edge RTT → higher throughput.
            scan_mode: ScanMode::Balanced,
            ip_version: IpVersion::V4,
            noize: "off".into(),
            noize_jc: 5,
            noize_jmin: 50,
            noize_jmax: 128,
            noize_interval_ms: 0,
            routing_mode: RoutingMode::SystemProxy,
            socks_port: 1819,
            http_port: 1820,
            start_minimized: false,
            launch_at_login: false,
            engine_path: String::new(),
            peer: String::new(),
            quic_initial_frag: false,
            quic_initial_frag_size: 96,
        }
    }
}

pub(crate) fn config_dir(app: &AppHandle) -> Result<PathBuf, CommandError> {
    app.path().app_config_dir().map_err(CommandError::from)
}

pub(crate) fn settings_path(app: &AppHandle) -> Result<PathBuf, CommandError> {
    Ok(config_dir(app)?.join("settings.json"))
}

/// `--repair-proxy`: recovery entry point for a user whose system proxy still
/// points at an engine that died. The app restores the registry state and exits
/// instead of opening a window they would have to fight with. Reading argv is the
/// same operation on every platform, so this is deliberately not `cfg`-gated:
/// the call site in `setup` is not either, and gating it left the shell unable to
/// compile for Linux and macOS, where CI never builds it.
pub(crate) fn repair_proxy_requested() -> bool {
    std::env::args().any(|a| a == "--repair-proxy")
}

/// `--minimized`, the flag `autostart::set(true)` writes into the HKCU\Run value.
/// Without it the launch-at-login path only ever consulted `start_minimized` from
/// settings.json, so enabling autostart dropped a full window on the desktop at
/// every logon.
pub(crate) fn start_minimized_requested() -> bool {
    std::env::args().any(|a| a == "--minimized")
}

pub(crate) fn proxy_recovery_path(app: &AppHandle) -> Result<PathBuf, CommandError> {
    Ok(config_dir(app)?.join("proxy-recovery.json"))
}

/// Decode the contents of `settings.json`, distinguishing "absent" from
/// "damaged". Public so the corruption path is unit-testable without an app.
pub fn decode_settings_text(text: &str) -> Result<Settings, CommandError> {
    serde_json::from_str::<Settings>(text).map_err(|e| CommandError {
        code: "settings_corrupt",
        message: format!("settings.json is not readable ({e}); refusing to overwrite it"),
        field: Some("settings"),
    })
}

/// Read the persisted settings.
///
/// A malformed file used to be folded into `Settings::default()` here, and the
/// frontend's autosave (debounced at ~400 ms) then wrote those defaults back
/// over the user's real protocol / ports / obfuscation settings. Absent is a
/// first run and still yields defaults; *damaged* is now an error the UI can
/// show and, crucially, gate its persist effect on.
pub(crate) fn load_settings_file(app: &AppHandle) -> Result<Settings, CommandError> {
    let path = settings_path(app)?;
    match fs::read_to_string(&path) {
        Ok(text) => decode_settings_text(&text),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Settings::default()),
        Err(e) => Err(CommandError::new(
            "settings_unreadable",
            format!("cannot read {}: {e}", path.display()),
        )),
    }
}

/// For readers that only *launch* something and never write the file back: a
/// damaged settings.json must not disable the route sweep or the diagnostics
/// export, but the reason has to be in the log rather than silent.
pub(crate) fn load_settings_or_defaults(app: &AppHandle) -> Settings {
    load_settings_file(app).unwrap_or_else(|e| {
        eprintln!("settings unusable ({e}); continuing with defaults for this read");
        Settings::default()
    })
}

/// Write `bytes` to `path` by way of an exclusively-created, uniquely named
/// temporary file that is flushed before it is renamed into place.
///
/// The settings file and the proxy-recovery journal used to share a fixed
/// `*.json.tmp` name written with `fs::write` and no `sync_all`: two writers (an
/// autosave and a connect, or two shells over the same profile) interleaved into
/// one temp file, and a rename could publish bytes that were still in the cache
/// across a power loss — for `proxy-recovery.json` that is the only record of
/// what the machine's proxy was before Aether touched it. Same discipline as the
/// DPAPI envelope write. Public so the temp-file discipline is testable.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    let file_name = path
        .file_name()
        .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::InvalidInput))?
        .to_string_lossy()
        .into_owned();
    let tmp = path.with_file_name(format!(
        "{file_name}.{}.{}.tmp",
        std::process::id(),
        rand::random::<u32>()
    ));
    let inner = || -> std::io::Result<()> {
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            // Owner-only from the first byte: these files are written next to the
            // DPAPI key where `restrict_directory_acl` is a no-op.
            opts.mode(0o600);
        }
        let mut file = opts.open(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&tmp, path)?;
        Ok(())
    };
    let result = inner();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

pub(crate) fn save_settings_file(app: &AppHandle, settings: &Settings) -> Result<(), CommandError> {
    let path = settings_path(app)?;
    let parent = path.parent().ok_or("invalid config path")?;
    fs::create_dir_all(parent).map_err(CommandError::from)?;
    restrict_directory_acl(parent)?;
    let json = serde_json::to_vec_pretty(settings).map_err(CommandError::from)?;
    write_atomic(&path, &json).map_err(CommandError::from)
}

/// The obfuscation profile names the engine is willing to run. Shared by
/// `validate_settings` (the Settings form) and the `scan` command: the scanner
/// used to take `noize` straight from the webview into `AETHER_NOIZE`, so a
/// profile could reach the engine's environment through a path that bypassed
/// every rule this list encodes.
pub const NOIZE_VOCABULARY: &[&str] = &[
    "off",
    "none",
    "light",
    "low",
    "medium",
    "balanced",
    "firewall",
    "default",
    "high",
    "gfw",
    "max",
    "aggressive",
    "heavy",
    "custom",
];

/// One reading of `noize` for a child environment: absent means "off", anything
/// outside [`NOIZE_VOCABULARY`] is refused rather than forwarded.
pub(crate) fn validated_noize(noize: Option<&str>) -> Result<&'static str, CommandError> {
    let requested = noize.unwrap_or("off").trim();
    NOIZE_VOCABULARY
        .iter()
        .find(|o| o.eq_ignore_ascii_case(requested))
        .copied()
        .ok_or_else(|| {
            CommandError::validation(
                "noize",
                format!("noize must be one of: {}", NOIZE_VOCABULARY.join(", ")),
            )
        })
}

pub fn validate_settings(settings: &Settings) -> Result<(), CommandError> {
    for (field, name, port) in [
        ("httpPort", "HTTP", settings.http_port),
        ("socksPort", "SOCKS5", settings.socks_port),
    ] {
        if !(1024..=65535).contains(&port) {
            return Err(CommandError::validation(
                field,
                format!("{name} port must be 1024–65535 (got {port})"),
            ));
        }
    }
    if settings.http_port == settings.socks_port {
        return Err(CommandError::validation(
            "httpPort",
            "HTTP and SOCKS5 ports must differ",
        ));
    }
    // `protocol`, `transport`, `scanMode`, `ipVersion` and `routingMode` are not
    // checked here any more: they are `wire_enum!` types, so a value outside the
    // vocabulary cannot be built in the first place. That removes the drift this
    // list was papering over — `ipVersion` allowed `auto/4/6/v4/v6/ipv4/ipv6/dual`
    // but not `"both"`, which is the exact string the Scanner's Dual-Stack row and
    // the Settings select both send. A valid choice was refused on save and
    // hard-broke the Connect button while the same label worked everywhere else,
    // and `"thorogh"` sat in the list as a legal scan mode.
    //
    // The first argument is the `Settings` key in the name the frontend uses,
    // because that is what the form needs in order to mark the right input: a
    // rejected value otherwise has nowhere to go but the log, and the save
    // spinner never stops.
    let allow = |field: &'static str, val: &str, opts: &[&str]| -> Result<(), CommandError> {
        if opts.iter().any(|o| o.eq_ignore_ascii_case(val.trim())) {
            Ok(())
        } else {
            Err(CommandError::validation(
                field,
                format!("{field} must be one of: {}", opts.join(", ")),
            ))
        }
    };
    allow("noize", &settings.noize, NOIZE_VOCABULARY)?;
    if settings.noize.eq_ignore_ascii_case("custom") {
        if settings.noize_jmax < settings.noize_jmin {
            return Err(CommandError::validation(
                "noizeJmax",
                "custom obfuscation: max size must be >= min size",
            ));
        }
        // One message for three different inputs is a message nobody can act on,
        // so each bound reports the field it broke.
        if settings.noize_jc > 64 {
            return Err(CommandError::validation(
                "noizeJc",
                format!(
                    "custom obfuscation: junk packet count must be <= 64 (got {})",
                    settings.noize_jc
                ),
            ));
        }
        if settings.noize_jmax > 2048 {
            return Err(CommandError::validation(
                "noizeJmax",
                format!(
                    "custom obfuscation: max size must be <= 2048 (got {})",
                    settings.noize_jmax
                ),
            ));
        }
        if settings.noize_interval_ms > 5000 {
            return Err(CommandError::validation(
                "noizeIntervalMs",
                format!(
                    "custom obfuscation: interval must be <= 5000 ms (got {})",
                    settings.noize_interval_ms
                ),
            ));
        }
    }
    // `routingMode` is a `wire_enum!` type now, so the three values are the only
    // ones that can reach here.
    // A custom engine path is checked for existence here rather than at connect,
    // where the allow-list would refuse it and the user would be left with a
    // "binary is not trusted" error for a path they typed themselves. It used to
    // be validated nowhere: the settings form persists on a 400 ms debounce, so a
    // half-typed path reached the disk as the configured engine.
    if !settings.engine_path.trim().is_empty() && !Path::new(settings.engine_path.trim()).is_file()
    {
        return Err(CommandError::validation(
            "enginePath",
            format!(
                "engine path does not exist as a file: {}",
                settings.engine_path.trim()
            ),
        ));
    }
    Ok(())
}

/// `save_settings`'s body: it runs `icacls` on the config directory and writes the
/// registry Run key, both of which are child-process waits.
pub(crate) fn save_settings_blocking(
    app: AppHandle,
    settings: Settings,
) -> Result<(), CommandError> {
    validate_settings(&settings)?;
    save_settings_file(&app, &settings)?;
    #[cfg(windows)]
    autostart::set(settings.launch_at_login)?;
    Ok(())
}

/// The settings that decide what the engine actually does, on one line.
///
/// Every driver of the engine — the window's Connect, the tray's Connect, an exit
/// teardown — has to name what it started, because the tray can only see the file
/// while the form can hold unsaved edits. A log line that says "started with the
/// saved settings" without saying *which* is not evidence of anything.
pub fn describe_settings(settings: &Settings) -> String {
    let peer = if settings.peer.trim().is_empty() {
        "none"
    } else {
        settings.peer.trim()
    };
    format!(
        "protocol={} transport={} scan={} ip={} routing={} socks={} http={} noize={} peer={}",
        settings.protocol,
        settings.transport,
        settings.scan_mode,
        settings.ip_version,
        settings.routing_mode,
        settings.socks_port,
        settings.http_port,
        settings.noize,
        peer,
    )
}

/// How stale the copy on disk is: the answer to "did the window's last edit make
/// it into the file this action just read?", which is the only form in which the
/// tray-vs-form disagreement can be diagnosed after the fact.
pub(crate) fn settings_age(app: &AppHandle) -> String {
    let Ok(path) = settings_path(app) else {
        return "at an unresolved location".into();
    };
    match fs::metadata(&path).and_then(|m| m.modified()) {
        Ok(at) => {
            let Ok(elapsed) = at.elapsed() else {
                // A clock in the future (a DST/NTP correction after the write) says
                // nothing about age except that the stamp is not trustworthy.
                return "with a timestamp this clock cannot age".into();
            };
            let secs = elapsed.as_secs();
            let span = if secs < 60 {
                format!("{secs} s")
            } else if secs < 3600 {
                format!("{} m", secs / 60)
            } else {
                format!("{} h", secs / 3600)
            };
            format!("{span} ago")
        }
        // No file at all is a first run, not a stale read — and the defaults the
        // caller is about to use were never seen by the user.
        Err(_) => "never (no settings.json on disk yet)".into(),
    }
}

/// The fields two settings values disagree on, by the name the frontend uses.
///
/// The names match `Settings`' camelCase serialisation so a user can point at the
/// row in the form that differs.
pub fn settings_differences(a: &Settings, b: &Settings) -> Vec<&'static str> {
    let mut out = Vec::new();
    macro_rules! cmp {
        ($field:literal, $left:expr, $right:expr) => {
            if $left != $right {
                out.push($field);
            }
        };
    }
    cmp!("protocol", a.protocol, b.protocol);
    cmp!("transport", a.transport, b.transport);
    cmp!("scanMode", a.scan_mode, b.scan_mode);
    cmp!("ipVersion", a.ip_version, b.ip_version);
    cmp!("noize", a.noize.trim(), b.noize.trim());
    cmp!("noizeJc", a.noize_jc, b.noize_jc);
    cmp!("noizeJmin", a.noize_jmin, b.noize_jmin);
    cmp!("noizeJmax", a.noize_jmax, b.noize_jmax);
    cmp!("noizeIntervalMs", a.noize_interval_ms, b.noize_interval_ms);
    cmp!("routingMode", a.routing_mode, b.routing_mode);
    cmp!("socksPort", a.socks_port, b.socks_port);
    cmp!("httpPort", a.http_port, b.http_port);
    cmp!("enginePath", a.engine_path.trim(), b.engine_path.trim());
    cmp!("peer", a.peer.trim(), b.peer.trim());
    cmp!("quicInitialFrag", a.quic_initial_frag, b.quic_initial_frag);
    cmp!(
        "quicInitialFragSize",
        a.quic_initial_frag_size,
        b.quic_initial_frag_size
    );
    out
}
