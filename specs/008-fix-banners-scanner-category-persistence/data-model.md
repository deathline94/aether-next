# Data Model & Configuration: Banners, Scanner Inputs & Category Persistence

## Entities

### DiscoveredEndpoint
Represents an endpoint discovered and verified during scanning.

| Field | Type | Description |
| :--- | :--- | :--- |
| `addr` | `string` | Socket address string (`IP:port`, e.g. `162.159.198.240:443`) |
| `rtt` | `string` | Formatted latency representation (e.g. `142ms`) |
| `rttMs` | `number` | Numeric round-trip latency in milliseconds |
| `protocol` | `string` | Protocol identifier (`MASQUE H3`, `MASQUE H2`, `WireGuard`) |

### ScannerFormSettings
Defines the parameters entered in the Scanner Tab form.

| Field | Type | Validation / Constraints | Default |
| :--- | :--- | :--- | :--- |
| `protocol` | `enum` | `"masque-h3" \| "masque-h2" \| "wireguard"` | `"masque-h3"` |
| `ipScan` | `enum` | `"v4" \| "v6" \| "both"` | `"v4"` |
| `concurrency` | `number` | `min: 1`, `max: 2000`, step: `10` (manual integer: 1–2000) | `250` |
| `timeoutMs` | `number` | `min: 100`, `max: 30000`, step: `100` (manual: 100–30000) | `6000` |
| `noize` | `string` | `"off" \| "light" \| "medium" \| "high" \| "max" \| "custom"` | `"off"` |

### CategoryEndpointMap (State Model)
State representation of discovered endpoints partitioned by protocol category.

```typescript
interface CategoryEndpoints {
  "masque-h3": DiscoveredEndpoint[];
  "masque-h2": DiscoveredEndpoint[];
  "wireguard": DiscoveredEndpoint[];
}
```

When a scan begins for protocol $P$:
$$\text{endpoints}_{\text{next}} = \{ e \in \text{endpoints}_{\text{current}} \mid \text{category}(e) \neq P \}$$
As hits arrive for $P$, they append to the active list and sort by `rttMs`.
