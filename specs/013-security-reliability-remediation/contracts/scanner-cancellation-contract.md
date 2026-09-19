# Contract: Prompt Scanner Cancellation & Probe Timeouts

**Feature**: `013-security-reliability-remediation`
**Target Components**: `aether/src/prober.rs`, `aether/src/main.rs`, `AetherBridge.kt`, `useScanner.ts`

---

## 1. Cooperative Cancellation Architecture

### Invariants:
1. `hunt_best` MUST observe cancellation within < 10 ms of signal arrival, even if all ongoing network probes are stalled or pending.
2. In-flight candidate probes must hold a child cancellation token and abort socket connection attempts immediately when the token is cancelled.
3. Upon cancellation, `hunt_best` finalizes and returns `Ok(best_candidate)` if at least one working endpoint was discovered prior to cancellation, or `Err(AetherError::Other("scan cancelled"))` if zero working endpoints were found.

### Rust Core Signature Contract

```rust
// aether/src/prober.rs

pub struct ScanCancellationToken {
    inner: tokio_util::sync::CancellationToken,
}

impl ScanCancellationToken {
    pub fn new() -> Self;
    pub fn cancel(&self);
    pub fn is_cancelled(&self) -> bool;
    pub fn child_token(&self) -> tokio_util::sync::CancellationToken;
}

pub async fn hunt_best_with_token(
    config: &ProbeConfig,
    ports: &[u16],
    ip: IpScan,
    mode: ScanMode,
    cancel_token: &ScanCancellationToken,
    verify: &VerifyFn<'_>,
) -> Result<ProbeResult>;
```

---

## 2. Unified Probe Timeout Contract

All client platforms and the core Rust network engine adhere to the following single source of truth:

| Tier | Setting / Constant | Minimum | Default | Maximum |
|---|---|---|---|---|
| **Android UI** (`useScanner.ts`) | `probeTimeoutMs` | 3000 ms | 6000 ms | 15000 ms |
| **Android Bridge** (`AetherBridge.kt`) | `timeoutMs` | 3000 ms | 6000 ms | 15000 ms |
| **Desktop UI** (`useScanner.ts`) | `probeTimeoutMs` | 3000 ms | 6000 ms | 15000 ms |
| **Core Engine** (`prober.rs`) | `timeout_per_probe` | 3000 ms (fast) / 5000 ms (H3) | Configured | 15000 ms |

Validation Rule:
If any layer receives a probe timeout value `< 3000 ms`, it is automatically clamped to `3000 ms`. Expensive cryptographic probes (e.g. MASQUE H3) enforce a hard protocol floor of `5000 ms`.
