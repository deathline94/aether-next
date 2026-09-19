# Process Supervisor Barrier Contract

## Process Lifecycle & Termination Guarantee

### API Contract
```kotlin
fun stopAndWait(timeoutMs: Long): Boolean
```

### Invariants

1. **State Retention on Termination Failure**:
   - If the underlying process does not terminate within `timeoutMs` (including graceful `destroy()` and forcible `destroyForcibly()` escalations):
     - `state` remains `SupervisorState.STOPPING`
     - `running` remains `true`
     - `process` reference is retained
     - Returns `false`
2. **State Transition on Termination Success**:
   - Only when `process.waitFor()` returns exit status confirmation:
     - `state` transitions to `SupervisorState.IDLE`
     - `running` becomes `false`
     - `process` is cleared (`null`)
     - Returns `true`
3. **Caller Enforcement**:
   - `SessionController.connect`:
     ```kotlin
     if (!runner.stopAndWait(3000)) {
         emitError("Previous engine process is still terminating; launch aborted")
         return
     }
     ```
   - `SessionController.scan`:
     ```kotlin
     if (!runner.stopAndWait(3000)) {
         emitError("Previous engine process is still terminating; scan aborted")
         return
     }
     ```
4. **Testability**:
   - `EngineRunner` accepts an optional `ProcessLauncher` interface:
     ```kotlin
     interface ProcessLauncher {
         fun launch(command: List<String>, env: Map<String, String>): Process
     }
     ```
   - Default implementation delegates to `ProcessBuilder(command).start()`.
