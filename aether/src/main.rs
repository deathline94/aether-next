mod account;
mod aethernoize;
mod config;
mod consts;
mod dns;
mod engine_config;
mod error;
mod http_proxy;
mod cache;
mod masque;
mod masque_h2;
mod mtu;
mod lastconn;
mod netstack;
mod noize;
mod obfuscation;
mod prober;
mod quic;
mod routing_plane;
mod runtime_env;
mod session;
mod session_event;
mod socks;
mod tls;
#[cfg(windows)]
mod tun_win;
mod tunnel;
mod tunnelping;
mod wireguard;

use engine_config::EngineConfig;
use error::{AetherError, Result};
use session_event::SessionEvent;

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp_millis()
        .init();

    install_netstack_panic_guard();
    let session = session::run_session(EngineConfig::from_env()?);
    let result = if std::env::var("AETHER_CONTROL_STDIN").as_deref() == Ok("1") {
        tokio::select! {
            result = session => result,
            _ = shutdown_request() => {
                log::info!("[+] graceful shutdown requested");
                Ok(())
            }
        }
    } else {
        session.await
    };
    if let Err(ref e) = result {
        let message = match e {
            AetherError::NoCleanEndpoint => {
                "No working gateway found. Try HTTP/2, another scan mode, or a different network."
                    .to_string()
            }
            other => other.to_string(),
        };
        log::error!("[-] session failed: {message}");
        session_event::emit(SessionEvent::Error { message });
        tokio::time::sleep(std::time::Duration::from_millis(80)).await;
    }
    result
}

async fn shutdown_request() {
    use tokio::io::{AsyncBufReadExt, BufReader};

    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    while let Ok(Some(line)) = lines.next_line().await {
        if line.trim().eq_ignore_ascii_case("shutdown") {
            return;
        }
    }
}

fn install_netstack_panic_guard() {
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let from_netstack = info
            .location()
            .map(|l| l.file().contains("smoltcp"))
            .unwrap_or(false);
        if from_netstack {
            log::debug!("[netstack] recovered from a malformed segment: {info}");
        } else {
            default_hook(info);
        }
    }));
}
