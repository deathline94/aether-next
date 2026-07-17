use serde::Serialize;

/// Structured events for GUI/CLI consumers. Printed as one JSON line:
/// `AETHER_EVENT {...}`
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SessionEvent {
    IdentityReady {
        device_id: String,
        ipv4: String,
    },
    EndpointSelected {
        addr: String,
        protocol: String,
    },
    ProxyReady {
        socks: String,
        http: String,
    },
    TunnelReady {
        transport: String,
    },
    TunReady,
    Connected {
        detail: String,
    },
    Error {
        message: String,
    },
}

pub fn emit(event: SessionEvent) {
    if let Ok(json) = serde_json::to_string(&event) {
        // Always info so default filter shows it; prefix is the protocol.
        log::info!("AETHER_EVENT {json}");
    }
}
