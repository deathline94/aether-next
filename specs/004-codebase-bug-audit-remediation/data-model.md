# Data Model: Comprehensive Codebase Bug Audit & Precision Remediation

## 1. Entities & Structural Definitions

### 1.1 NetStack Packet Ring (`StackDevice`)
Manages packet queues inside the userspace smoltcp virtual network interface.
- **Fields**:
  - `rx: VecDeque<Vec<u8>>`: Inbound IP packet buffer from the tunnel to smoltcp.
  - `tx: VecDeque<Vec<u8>>`: Outbound IP packet buffer from smoltcp to the tunnel.
  - `mtu: usize`: Maximum transmission unit (clamped to tunnel MTU).
- **Invariants**:
  - Outbound packets in `tx` must retain strict FIFO ordering across batch flushes and queue-full retries.
  - ACK-sized packets (<= 128 bytes) are prioritized, but deferred data packets must maintain their relative sequence when re-queued.

### 1.2 DNS Server Configuration (`configured_dns_servers`)
Represents parsed DNS resolver endpoints used by SOCKS5 and HTTP proxy resolution.
- **Fields**:
  - `ip: IpAddr`: IPv4 or IPv6 address of the resolver.
  - `port: u16`: UDP/TCP port (defaults to 53 when unspecified).
- **Validation Rules**:
  - Bare IPv4 addresses (e.g. `1.1.1.1`) -> `1.1.1.1:53`.
  - Bare IPv6 addresses (e.g. `2606:4700:4700::1111`) -> `[2606:4700:4700::1111]:53`.
  - Bracketed IPv6 with port (e.g. `[2606:4700:4700::1111]:5353`) -> `[2606:4700:4700::1111]:5353`.
  - IPv4 with port (e.g. `1.1.1.1:5353`) -> `1.1.1.1:5353`.

### 1.3 SOCKS5 UDP Association Mapping (`UdpClientSession`)
Routes UDP datagrams between local client sockets and remote Internet targets through smoltcp.
- **Fields**:
  - `client_addr: SocketAddr`: Originating address/port of the local client.
  - `target_addr: SocketAddr`: Remote destination address/port requested by the client.
  - `last_seen: Instant`: Timestamp of the most recent datagram for TTL expiration.
- **State Transitions**:
  - Active: Datagram received from client -> maps `target_addr` to `client_addr`.
  - Reply: Inbound datagram from stack from `target_addr` -> forwarded to mapped `client_addr`.
  - Expired: Entry purged if no traffic observed within session timeout.

### 1.4 HTTP Proxy Request Target (`rewrite_absolute_uri`)
Parsed target information from an HTTP request line.
- **Fields**:
  - `method: String`: CONNECT, GET, POST, etc.
  - `target: String`: Original request URI.
  - `path: String`: Origin-form path including query string (e.g. `/index.html?param=value`).
  - `version: String`: HTTP version (e.g. `HTTP/1.1`).
- **Validation Rules**:
  - Query parameters following `?` must be preserved in origin-form rewriting regardless of whether a leading slash was present before the query.

### 1.5 Desktop Settings (`Settings`)
Persisted configuration for tunnel protocols, network ports, and obfuscation.
- **Fields**:
  - `protocol`: `"masque"` | `"wireguard"` | `"gool"`.
  - `transport`: `"h2"` | `"h3"`.
  - `http_port`: `u16` (1024..=65535).
  - `socks_port`: `u16` (1024..=65535, must differ from `http_port`).
  - `noize`: Canonical profile (`"off"` | `"light"` | `"medium"` | `"high"` | `"max"` | `"custom"`).
- **Validation Rules**:
  - `http_port != socks_port`.
  - Saving is blocked until both ports are within valid ranges.

### 1.6 Desktop Runtime State (`RuntimeState`)
Live operational state emitted to the GUI via Tauri IPC.
- **Fields**:
  - `status`: `"disconnected"` | `"connecting"` | `"connected"` | `"error"`.
  - `detail`: Descriptive status message or error text.
  - `pid`: Process identifier of running engine or `null`.
  - `endpoint`: Currently selected Cloudflare edge address or `null`.
