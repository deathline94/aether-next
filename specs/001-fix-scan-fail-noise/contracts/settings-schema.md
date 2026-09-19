# Interface Contract: Settings Schema & Default Values

## Purpose
Defines the persistent configuration model across desktop (`settings.json`), Tauri Rust deserializer, and Android SharedPreferences.

## Schema Attributes (CamelCase in JSON)

| Field | Type | Default Value | Validation Constraints |
|---|---|---|---|
| `protocol` | `"masque" \| "wireguard" \| "gool"` | `"masque"` | Must be one of enumerated protocols |
| `transport` | `"h2" \| "h3"` | `"h2"` | Applicable to MASQUE |
| `scanMode` | `"turbo" \| "balanced" \| "thorough" \| "stealth"` | `"balanced"` | Endpoint discovery depth |
| `ipVersion` | `"v4" \| "v6" \| "both"` | `"v4"` | IP stack filter |
| `noize` | `string` | `"off"` | Profile name (`"off"`, `"light"`, `"medium"`, `"high"`, `"max"`, `"custom"`) |
| `noizeJc` | `number` | `5` | 1–64 junk packets |
| `noizeJmin` | `number` | `50` | 1–2048 bytes |
| `noizeJmax` | `number` | `128` | >= `noizeJmin`, <= 2048 bytes |
| `noizeIntervalMs` | `number` | `0` | 0–5000 ms |
| `routingMode` | `"system-proxy" \| "proxy-only" \| "tun"` | `"system-proxy"` | Operating routing mode |
| `socksPort` | `number` | `1819` | 1024–65535, != `httpPort` |
| `httpPort` | `number` | `1820` | 1024–65535, != `socksPort` |
