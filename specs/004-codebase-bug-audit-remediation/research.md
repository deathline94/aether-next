# Research & Technical Decisions: Comprehensive Codebase Bug Audit & Precision Remediation

## Phase 0: Technical Decisions & Rationale

### 1. Netstack Packet Ordering Under Backpressure (`aether/src/netstack.rs`)
- **Decision**: In `flush_tx`, when `outbound_tx.try_send(pkt)` fails with `TrySendError::Full(pkt)`, re-queue `pkt` at the front of `deferred`, then transfer `deferred` back to `s.device.tx` preserving exact FIFO order.
- **Rationale**: The previous implementation reversed the elements of `deferred` with `deferred.pop_back()` into `s.device.tx.push_front()`, inverting the order of queued packets. When `outbound_tx` was congested, packets were scrambled, leading to out-of-order TCP deliveries, duplicate ACKs, and window reduction.
- **Alternatives Considered**:
  - Dropping packets on queue-full: Rejected because userspace tunnel drops cause synthetic packet loss and degrade connection quality.
  - Unbounded queue: Rejected because it causes multi-gigabyte memory growth and allocator crashes under continuous high-speed downloads.

### 2. SOCKS5 IPv6 DNS Configuration Parsing (`aether/src/socks.rs`)
- **Decision**: In `configured_dns_servers()`, attempt parsing candidate strings first as `IpAddr`. If successful, create a `SocketAddr` with default port 53. If not, attempt parsing as `SocketAddr` (supporting bracketed `[ipv6]:port` and `ipv4:port`).
- **Rationale**: Standard IPv6 literals like `2606:4700:4700::1111` contain colons. The previous logic (`p.contains(':')`) skipped appending `:53`, then failed to parse as `SocketAddr` because unbracketed IPv6 addresses cannot be parsed as `SocketAddr`.
- **Alternatives Considered**:
  - Requiring users to type brackets in UI/env: Rejected because standard DNS configuration in system tools and environment variables accepts bare IP addresses.
  - Regex splitting: Rejected as error-prone compared to Rust standard library `IpAddr` / `SocketAddr` parsing.

### 3. SOCKS5 UDP Associate Ephemeral Port Multiplexing (`aether/src/socks.rs`)
- **Decision**: Track UDP client sessions by mapping each target remote `SocketAddr` to the originating local client `SocketAddr`, or track active loopback client ports with an LRU/TTL table, and route downstream responses from `from_stack` to the specific client that addressed that remote host/port.
- **Rationale**: When multiple local threads or applications dispatch parallel UDP datagrams through a single SOCKS5 UDP association (common for DNS queries and WebRTC), overwriting a single `client` variable misdirects replies to the wrong local socket, causing packet loss.
- **Alternatives Considered**:
  - Refusing multiple local ports: Rejected because multi-socket clients are common on Windows and Android.
  - Single association per port: Rejected because RFC 1928 allows one SOCKS5 UDP association to handle datagrams from multiple ephemeral ports on the authorized client host.

### 4. HTTP Proxy Absolute URI Query String Preservation (`aether/src/http_proxy.rs`)
- **Decision**: In `rewrite_absolute_uri()`, check whether `rest` contains `/` or `?`. If `?` precedes `/` or no `/` is present, construct the path as `/{rest[question_idx..]}`.
- **Rationale**: An HTTP absolute URI like `http://example.com?query=val` is valid. Previously, `rest.find('/')` returned `None`, which replaced the target with `"/"`, silently erasing query parameters.
- **Alternatives Considered**:
  - Third-party URL parser: Rejected to avoid unnecessary dependencies and allocations on high-throughput proxy relays.

### 5. Windows TUN Route Scoping (`aether/src/tun_win.rs`)
- **Decision**: In `install_routes()`, specify `-InterfaceIndex $tunIf` when removing stale split-default routes (`0.0.0.0/1` and `128.0.0.0/1`).
- **Rationale**: Running `Remove-NetRoute` without an interface index deleted `0.0.0.0/1` and `128.0.0.0/1` across all network adapters on Windows, breaking coexisting VPN connections (such as corporate or second-tunnel interfaces). `remove_routes()` was already fixed in M1, but `install_routes()` had not been scoped.
- **Alternatives Considered**:
  - Leaving routes uncleaned: Rejected because stale routes from previous crashed sessions prevent the new tunnel from acquiring traffic.

### 6. Thread-Safe Configuration Lookup in `select_peer` (`aether/src/session.rs`)
- **Decision**: In `select_peer()`, replace `std::env::var("AETHER_PEER")` and `std::env::var("AETHER_WG_PEER")` with `runtime_env::var("AETHER_PEER")` and `runtime_env::var("AETHER_WG_PEER")`.
- **Rationale**: `runtime_env` provides synchronized in-memory storage populated from `EngineConfig`. Direct `std::env::var` calls bypass programmatic configuration and risk data races in multi-threaded async execution.
- **Alternatives Considered**:
  - Calling `std::env::set_var`: Rejected because `set_var` is unsafe and causes data races in multi-threaded Rust.

### 7. Desktop Direct Connect Error State Handling (`apps/desktop/src/hooks/useRuntime.ts`)
- **Decision**: In `connectToPeer()`, catch errors from `invoke("connect")` and set `runtime` state to `{ status: "error", detail: String(error), pid: null, endpoint: null }`.
- **Rationale**: The previous implementation only logged the error without updating `runtime`, leaving the UI stuck in the "Connecting" spinning state.
- **Alternatives Considered**:
  - Silently resetting to disconnected: Rejected because the user needs clear feedback explaining why the connection failed.

### 8. Desktop Auto-Save Validation Filter (`apps/desktop/src/hooks/useRuntime.ts`)
- **Decision**: In `persistSettings()`, check if `toSave.httpPort === toSave.socksPort` or if either port is outside `1024..=65535`. If invalid, abort the debounce timer and do not call `save_settings`.
- **Rationale**: When users type port numbers, intermediate states frequently violate port uniqueness. Sending these intermediate states causes backend validation errors and spams error logs.
- **Alternatives Considered**:
  - Only saving on explicit button click: Rejected because the application uses a reactive auto-save pattern for all settings.

### 9. Obfuscation Profile Options Synchronization (`apps/desktop/src/components/ScannerTab.tsx`)
- **Decision**: Synchronize the `<select>` options in `ScannerTab.tsx` with `SettingsTab.tsx` to include canonical names (`off`, `light`, `medium`, `high`, `max`, `custom`), mapping legacy aliases (`firewall` -> `medium`, `balanced` -> `medium`, `gfw` -> `high`).
- **Rationale**: When settings use `"firewall"` (the default in Aether), `ScannerTab` had no matching `<option>`, causing the select box to render blank or desynchronized.
- **Alternatives Considered**:
  - Keeping separate lists: Rejected because user settings and scanner probes share the same underlying engine noise engine.

### 10. Desktop Log Readiness String Parity (`apps/desktop/src-tauri/src/lib.rs`)
- **Decision**: Update `lib.rs` line 459 to check `line.contains("socks5 listening on") || line.contains("http proxy listening")`.
- **Rationale**: The engine logs `"socks5 listening on {listen}"`. Checking for `"socks5 server listening"` caused fallback readiness detection to miss the startup signal.

### 11. Android Production TLS Verification & Probe Timeout (`apps/android/`)
- **Decision**: In `EngineRunner.kt`, remove unconditional `put("AETHER_DANGEROUS_DISABLE_TLS_VERIFY", "1")` so SPKI pinning is enforced on Android. In `AetherBridge.kt`, set default probe timeout to 6000ms.
- **Rationale**: Disabling TLS verification compromises user privacy on untrusted mobile networks. Increasing probe timeout prevents false negative timeouts during QUIC handshakes over cellular latency.
- **Alternatives Considered**:
  - Hardcoded disabling: Rejected as a critical security vulnerability.
