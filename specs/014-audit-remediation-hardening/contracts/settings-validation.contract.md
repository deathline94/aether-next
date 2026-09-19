# Settings Validation Contract

## Mobile Bridge Settings Schema & Invariants

### Method Signature
```kotlin
fun validateSettings(json: String): ValidationResult
```

### JSON Schema Rules
```json
{
  "type": "object",
  "required": ["protocol", "transport", "routingMode"],
  "properties": {
    "protocol": {
      "type": "string",
      "enum": ["wireguard", "masque"]
    },
    "transport": {
      "type": "string",
      "enum": ["h2", "h3"]
    },
    "endpointPreset": {
      "type": "string",
      "enum": ["warp", "gool"]
    },
    "routingMode": {
      "type": "string",
      "enum": ["tun", "proxy-only", "system-proxy"]
    },
    "ipVersion": {
      "type": "string",
      "enum": ["v4", "v6", "both"]
    },
    "noiseMode": {
      "type": "string",
      "enum": ["off", "light", "medium", "high", "max", "custom"]
    },
    "scanMode": {
      "type": "string",
      "enum": ["turbo", "balanced", "thorough", "stealth", "ironclad"]
    },
    "proxyPort": {
      "type": "integer",
      "minimum": 1024,
      "maximum": 65535
    },
    "scanTimeoutMs": {
      "type": "integer",
      "minimum": 3000
    }
  }
}
```

### Protocol-Specific Bounds:
- If `protocol == "masque"` and `transport == "h3"`, `scanTimeoutMs` MUST be `>= 6000`.
- Unknown properties or unexpected enum strings return `ValidationResult.Error(field, message)`.
