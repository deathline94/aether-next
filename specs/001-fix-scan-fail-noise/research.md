# Research: Endpoint Discovery Failure State Reversion and Unified Noise Profiles

## Summary of Decisions

### Decision 1: Immediate Failure Termination & UI State Reset on Discovery Failure

- **Context**: When MASQUE H3 is selected and endpoint scanning yields no reachable gateways, the session previously fell back to a hardcoded anycast IP (`162.159.192.1:443`). In restricted networks, this IP is blackholed, forcing two consecutive 20-second connection timeouts. Furthermore, upon session failure, `aether/src/main.rs` returned `Err`, prompting Tokio runtime drop. On Windows, Tokio's `io::stdin()` thread performs a blocking OS read (`ReadFile`), preventing runtime shutdown and hanging the process indefinitely. As a result, Tauri's `watch_child` never detected child process exit, leaving `runtime.status` stuck at `"connecting"` and the power button stuck in the active ("DISCONNECT") state until clicked manually.
- **Decision**:
  1. In `aether/src/session.rs`, remove the fallback to `MASQUE_H3_ENDPOINT` when `select_peer` returns `NoCleanEndpoint`. Propagate `AetherError::NoCleanEndpoint` immediately.
  2. In `aether/src/main.rs`, when `result` is `Err`, emit `SessionEvent::Error { message }`, flush standard I/O, and terminate the process explicitly via `std::process::exit(1)`.
  3. In `apps/desktop/src-tauri/src/lib.rs`, ensure that when `AETHER_EVENT {"type":"error", ...}` is received or when the child exits non-zero, the application transitions to `status: "error"`, clears `connecting: false`, and tears down any proxy configurations.
  4. In `apps/android/.../SessionController.kt`, ensure `"error"` structured events and non-zero exit codes transition the runtime state to `status: "error"`, stopping foreground services.
- **Rationale**: A failed scan cannot recover by attempting a known-blocked anycast endpoint. Promptly failing and cleanly exiting frees OS thread resources and triggers immediate UI state transitions.
- **Alternatives Considered**:
  - *Keep anycast fallback*: Rejected because it delays failure feedback by 40+ seconds and always fails in the user's network environment.
  - *Rely on user manual disengagement*: Rejected because leaving the Start button hung while logs state failure violates fundamental UX principles.

---

### Decision 2: Align Noise Injection Profiles Across All 4 Protocols (Jc=5, Jmin=50, Jmax=128, Delay=0)

- **Context**: The user identified two proven working obfuscation formats in other WireGuard implementations:
  1. **Amnezia WireGuard format**:
     ```ini
     [Interface]
     PrivateKey = ...
     Jc = 5
     Jmin = 50
     Jmax = 128
     ```
  2. **v2rayN finalmask format**:
     ```json
     {
       "udp": [
         {
           "type": "noise",
           "settings": {
             "reset": "1-2",
             "noise": [
               { "rand": "50-128", "delay": "0" },
               { "rand": "50-128", "delay": "0" },
               { "rand": "50-128", "delay": "0" },
               { "rand": "50-128", "delay": "0" },
               { "rand": "50-128", "delay": "0" }
             ]
           }
         }
       ]
     }
     ```
  In Aether Next, noise was previously fragmented with different packet counts (2 for MASQUE, 3–6 for WireGuard), larger sizes (up to 190–256 bytes), and positive inter-packet delays (2–5 ms).
- **Decision**:
  1. In `aether/src/noize.rs` (MASQUE H2 & H3):
     - Update active profiles (`firewall`, `gfw`) to use `jc_before_hs: 5`, `jmin: 50`, `jmax: 128`, and `junk_interval: Duration::ZERO`.
     - Fast burst sending 5 junk packets without artificial sleep.
  2. In `aether/src/aethernoize.rs` (WireGuard & WARP-in-WARP / Gool):
     - Update active profiles (`balanced`, `light`, `aggressive`) to send 5 junk packets of 50–128 bytes with 0 ms delay (`junk_interval: Duration::ZERO`, `handshake_delay: Duration::ZERO`).
     - Align `jc_before_hs = 5`, `jmin = 50`, `jmax = 128`.
  3. In `aether/src/obfuscation.rs`:
     - Update default parameters when parsing env variables (`AETHER_NOIZE_JC=5`, `AETHER_NOIZE_JMIN=50`, `AETHER_NOIZE_JMAX=128`, `AETHER_NOIZE_INTERVAL_MS=0`).
  4. In UI configuration schemas (`apps/desktop/src/types.ts`, `apps/desktop/src-tauri/src/lib.rs`, `apps/android/src/types.ts`):
     - Update defaults to `noizeJc: 5`, `noizeJmin: 50`, `noizeJmax: 128`, `noizeIntervalMs: 0`.
- **Rationale**: Immediate 5-packet burst of small packets (50–128 bytes) matches the exact packet signature proven effective in bypassing firewall heuristics for both WireGuard UDP handshakes and QUIC Initial packets.
- **Alternatives Considered**:
  - *Retain 2–5ms jitter delay*: Rejected because the working v2rayN and Amnezia setups specify `"delay": "0"`; timing delays allow stateful DPI to correlate subsequent handshake packets.
