# Contract: Process Supervisor & VPN Lifecycle

**Feature**: `013-security-reliability-remediation`
**Target Components**: `EngineRunner.kt`, `SessionController.kt`, `AetherVpnService.kt`

---

## 1. Supervisor Lifecycle Interface

```kotlin
interface ProcessSupervisor {
    val state: SupervisorState
    val generation: Long
    
    /**
     * Launch engine in tunnel mode with provided settings.
     * Precondition: state must be IDLE.
     * Postcondition: on success, state transitions to CONNECTING.
     */
    fun startTunnel(settings: Settings): Result<Unit>
    
    /**
     * Launch engine in scan-only mode.
     * Precondition: state must be IDLE.
     * Postcondition: on success, state transitions to SCANNING.
     */
    fun startScan(params: ScanParams): Result<Unit>
    
    /**
     * Graceful stop with hard timeout fallback and blocking completion barrier.
     * Sends "cancel\n" if SCANNING, "shutdown\n" if CONNECTING/CONNECTED.
     * Awaits confirmed process exit up to timeoutMs before SIGKILL.
     * Postcondition: process handle is null, state is IDLE, generation incremented.
     */
    fun stopAndWait(timeoutMs: Long = 5000): Boolean
}
```

## 2. Direct Connect Auto-Teardown Contract

```text
Sequence: ConnectDirect Requested during active scan
1. UI / Caller calls SessionController.connect(settings)
2. SessionController checks supervisor.state:
   if (supervisor.state == SCANNING) {
       log.info("Active scan detected; stopping before direct connect")
       val stopped = supervisor.stopAndWait(3000)
       if (!stopped) {
           return Error("Failed to stop running scanner")
       }
   }
3. Proceed with standard tunnel connection.
```

## 3. VPN Establishment Lifecycle Guard

```text
Sequence: VpnService establishTun & Generation Verification
1. Worker captures val currentGen = vpnGeneration.incrementAndGet()
2. establishTun executes inside synchronized(lifecycleLock):
   if (stopRequested || currentGen != vpnGeneration.get()) return false
   val vpnFd = builder.establish() ?: return false
   tun = vpnFd
   return true
3. On worker thread completion:
   if (established && currentGen == vpnGeneration.get()) {
       mainHandler.post { SessionController.getOrNull()?.onVpnEstablished() }
   }
```
