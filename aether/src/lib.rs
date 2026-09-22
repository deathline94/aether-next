#![allow(unstable_name_collisions)] // fs2::FileExt::unlock vs future std method
#![allow(clippy::uninlined_format_args)] // style: log macros with separate args
#![allow(clippy::should_implement_trait)] // masque::next is not Iterator::next
#![allow(clippy::new_without_default)] // WgSessionCache::new has no meaningful default

pub mod account;
pub mod aethernoize;
pub mod cli;
pub mod config;
pub mod consts;
pub mod dns;
pub mod engine_config;
pub mod error;
pub mod h3_probe;
pub mod keyhandoff;
pub mod http_proxy;
pub mod cache;
pub mod masque;
pub mod masque_h2;
pub mod mtu;
pub mod lastconn;
pub mod netstack;
pub mod noize;
pub mod obfuscation;
pub mod prober;
pub mod quic;
pub mod routing_plane;
pub mod host_lock;
pub mod route_repair;
pub mod runtime_env;
pub mod session;
pub mod session_event;
pub mod socks;
pub mod tls;
#[cfg(windows)]
pub mod tun_win;
pub mod trust;
pub mod tunnel;
pub mod tunnelping;
pub mod wireguard;
#[cfg(windows)]
pub mod win_acl;
#[cfg(windows)]
pub mod win_exec;

pub use engine_config::EngineConfig;
pub use error::{AetherError, Result};
pub use session_event::SessionEvent;
