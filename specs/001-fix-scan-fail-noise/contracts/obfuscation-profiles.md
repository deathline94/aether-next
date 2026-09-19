# Interface Contract: Obfuscation Noise Profiles

## Purpose
Specifies the unified obfuscation parameters across all four supported protocols:
1. WireGuard (`wireguard`)
2. WARP-in-WARP / Gool (`gool`)
3. MASQUE over HTTP/2 (`masque` with `transport: h2`)
4. MASQUE over HTTP/3 (`masque` with `transport: h3`)

## Standard Profile Definition
For all protocols operating with noise enabled:

```text
Parameter        Value
-----------------------------------
Junk Count (Jc)  5
Min Size (Jmin)  50 bytes
Max Size (Jmax)  128 bytes
Interval (delay) 0 milliseconds
Handshake Delay  0 milliseconds
Payload Pattern  Random pseudo-random bytes per packet
```

## Transport Invariants

### 1. MASQUE H3 & H2 (`aether/src/noize.rs`)
- Prior to QUIC Initial ClientHello or TLS ClientHello dispatch:
  - Exactly 5 UDP datagrams are transmitted to the target server endpoint.
  - Each datagram size is selected uniformly at random in `[50, 128]`.
  - Zero inter-packet sleep is introduced.

### 2. WireGuard & WARP-in-WARP (`aether/src/aethernoize.rs`)
- Prior to WireGuard Handshake Initiation dispatch:
  - Exactly 5 UDP datagrams are transmitted to the WireGuard peer endpoint.
  - Each datagram size is selected uniformly at random in `[50, 128]`.
  - Zero inter-packet sleep is introduced.

### 3. WireGuard Configuration Representation
- Exported or saved WireGuard client configuration profiles contain:
  ```ini
  [Interface]
  PrivateKey = <base64>
  Address = <ipv4>/32
  DNS = 1.1.1.1
  Jc = 5
  Jmin = 50
  Jmax = 128
  ```
