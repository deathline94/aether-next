package app.aethernext

import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.util.Log
import org.json.JSONObject
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Mirrors desktop session orchestration: start engine, parse logs/events, VPN optional.
 *
 * Full VPN mode: after local SOCKS is up, start [AetherVpnService] which runs
 * hev-socks5-tunnel (tun2socks) against 127.0.0.1:socksPort.
 */
class SessionController(
    private val context: Context,
    emitter: (event: String, payload: JSONObject) -> Unit,
    runnerFactory: ((onLine: (String) -> Unit, onExit: (Int?, Boolean) -> Unit) -> EngineRunner)? = null,
) {
    /**
     * The last published state. T215: this used to be one mutable `RuntimeState`
     * that several threads wrote field-by-field, so `toJson()` could serialise
     * `status="connected"` next to a previous session's `pid`, or a `connected`
     * status with no tunnel behind it. Writes now build a whole new value under
     * [stateLock] and publish it in one @Volatile store, and [getState] hands out
     * that reference — which nobody can mutate afterwards, because `RuntimeState`
     * is immutable once published.
     */
    @Volatile
    private var runtime = RuntimeState()

    private val stateLock = Any()

    fun setEmitter(fn: (event: String, payload: JSONObject) -> Unit) {
        defaultEmitter = fn
    }

    /** The process-wide sink, set by [get]; per-activity sinks go through [attachUi]. */
    @Volatile
    private var defaultEmitter: (event: String, payload: JSONObject) -> Unit = emitter

    /** The one path every event takes: [fanOut]. Never reassigned, so a lifecycle
     *  change in one activity cannot silence another activity's events. */
    private val emit: (event: String, payload: JSONObject) -> Unit = { event, payload ->
        fanOut(event, payload)
    }

    /**
     * The sinks that are actually attached, keyed by their owner (an activity).
     *
     * The controller is a process singleton, so the single `emit` field gave a task
     * swipe two equally wrong options: leave a dead WebView as the sink, or silence
     * the whole session — which is what happened, and left the engine and a
     * full-device tunnel running with no way for any UI to see or stop them (T2xx).
     * Sinks are now registered per owner and removed when that owner dies; the
     * session only goes silent when the last one is gone, and that is a fact callers
     * can act on.
     */
    private val emitterLock = Any()
    private val uiEmitters = LinkedHashMap<Any, (event: String, payload: JSONObject) -> Unit>()

    /** Attach [owner]'s sink. Idempotent per owner, so `onResume` may re-attach. */
    fun attachUi(owner: Any, fn: (event: String, payload: JSONObject) -> Unit) {
        synchronized(emitterLock) { uiEmitters[owner] = fn }
        reportUnfinishedSession()
    }

    /**
     * Tell the console once per process that the previous session did not end
     * because it was asked to.
     *
     * The ledger in [SessionLedger] is only cleared by a teardown that ran, so an
     * entry left behind means the system killed the app mid-tunnel. Without this
     * the user sees STANDBY and has no way to know the difference between "I
     * stopped it" and "it stopped, and my traffic is bare".
     */
    private fun reportUnfinishedSession() {
        if (!ledgerReported.compareAndSet(false, true)) return
        val since = ledger.takeUnfinished() ?: return
        val message = SessionLedger.messageFor(since, System.currentTimeMillis())
        Log.w(TAG, message)
        emit("session://log", JSONObject().put("level", "error").put("message", message))
        setRuntime("error", message, null, null)
    }

    /**
     * Remove [owner]'s sink.
     *
     * @return true when nothing is listening any more — the caller's cue that a
     *   tunnel no UI can reach should not stay up.
     */
    fun detachUi(owner: Any): Boolean = synchronized(emitterLock) {
        uiEmitters.remove(owner)
        uiEmitters.isEmpty()
    }

    /** Whether at least one UI sink is registered. */
    fun hasUi(): Boolean = synchronized(emitterLock) { uiEmitters.isNotEmpty() }

    private fun fanOut(event: String, payload: JSONObject) {
        try {
            defaultEmitter(event, payload)
        } catch (e: Exception) {
            Log.w(TAG, "the process sink threw for $event: ${e.message}")
        }
        val sinks = synchronized(emitterLock) { uiEmitters.values.toList() }
        for (sink in sinks) {
            try {
                sink(event, payload)
            } catch (e: Exception) {
                Log.w(TAG, "a UI sink threw for $event and was dropped: ${e.message}")
                synchronized(emitterLock) { uiEmitters.values.removeIf { it === sink } }
            }
        }
    }

    /**
     * Tear the session down because no UI is left that could ever stop it.
     *
     * Safe to call from any thread and cheap to call twice: [disconnect] is guarded
     * by `tearingDown`. The activity's `onDestroy` may not block, so this is the form
     * it calls.
     */
    fun shutdownHeadless(reason: String = "no interface left to control the tunnel") {
        if (hasUi()) return
        if (runtime.status == "disconnected" && !VpnTunnel.up && !runner.isRunning()) return
        Log.w(TAG, "stopping the session headlessly: $reason")
        disconnect()
    }

    private val store = SettingsStore(context)
    /** Survives the process so an outside kill can be reported on next launch. */
    private val ledger = SessionLedger(context)
    private val ledgerReported = java.util.concurrent.atomic.AtomicBoolean(false)
    private val connectedOnce = AtomicBoolean(false)
    private val socksSeen = AtomicBoolean(false)
    private val tunnelSeen = AtomicBoolean(false)
    private val vpnStarted = AtomicBoolean(false)
    private val vpnEstablished = AtomicBoolean(false)
    private val tearingDown = AtomicBoolean(false)
    /// Set while a VPN teardown has been asked for but not yet acked by [AetherVpnService].
    private val vpnStopPending = AtomicBoolean(false)
    /// The engine's own `{"type":"connected"}` event — the only statement that can
    /// claim a working data path on its own (T129's fail-closed replacement for
    /// inferring it from log prose).
    private val engineAssertedConnected = AtomicBoolean(false)
    /// Malformed `AETHER_EVENT` lines this session, counted so the drop is visible
    /// rather than silent (T129).
    private val malformedEvents = java.util.concurrent.atomic.AtomicInteger(0)
    /// Events with a valid shape but a `type` this shell does not model.
    private val unknownEvents = java.util.concurrent.atomic.AtomicInteger(0)
    /// Whether the running scan has already produced a terminal event of its own.
    private val scanTerminalSent = AtomicBoolean(false)

    ///
    /// The standalone-scan run the UI started, echoed onto every `scan://event`.
    ///
    /// The UI drops a scan event whose run id is not the one it started, so a late
    /// terminal event from a cancelled scan cannot end the scan that is actually
    /// running. That guard was unreachable: the bridge accepted the id, this
    /// controller rebuilt the payload without it, and every event arrived
    /// unattributed (T2xx).
    @Volatile
    private var scanRunId: String = ""

    @Volatile
    private var settings = store.load()

    // ─── log coalescing (T2xx) ────────────────────────────────────────────────
    private val logLock = Any()
    private val logBatch = mutableListOf<JSONObject>()
    private val logDropped = java.util.concurrent.atomic.AtomicInteger(0)
    private val logFlushScheduled = AtomicBoolean(false)

    /**
     * A plain JVM scheduler on purpose: a `Handler(Looper.getMainLooper())` cannot be
     * constructed in a unit test, and the flush only ever calls [emit] — which the
     * activity already marshals to the UI thread.
     */
    private val logScheduler: java.util.concurrent.ScheduledExecutorService by lazy {
        java.util.concurrent.Executors.newSingleThreadScheduledExecutor { r ->
            Thread(r, "aether-log-batch").apply { isDaemon = true }
        }
    }

    private fun resetSessionFlags() {
        connectedOnce.set(false)
        socksSeen.set(false)
        tunnelSeen.set(false)
        vpnStarted.set(false)
        vpnEstablished.set(false)
        engineAssertedConnected.set(false)
    }

    private fun handleExit(code: Int?, isScan: Boolean) {
        if (isScan) {
            scanExitEvent(scanTerminalSent.get())?.let { emitScan(it) }
            if (runtime.status != "connected") {
                setRuntime("disconnected", "Ready", null, null)
            }
            return
        }
        val wasConnected = connectedOnce.get()
        resetSessionFlags()
        val isError = code != null && code != 0 && !wasConnected
        val vpnErr = stopVpnService()
        setRuntime(
            if (vpnErr != null) "error" else if (isError) "error" else "disconnected",
            vpnErr ?: if (isError) "Could not find a working gateway"
            else if (code == 0 || code == null) "Engine stopped"
            else "Engine exited ($code)",
            null,
            null,
        )
        context.stopService(Intent(context, EngineService::class.java))
    }

    internal val runner: EngineRunner = runnerFactory?.invoke(
        { line -> handleEngineLine(line) },
        { code, isScan -> handleExit(code, isScan) }
    ) ?: EngineRunner(
        context = context,
        onLine = { line -> handleEngineLine(line) },
        onExit = { code, isScan -> handleExit(code, isScan) },
    )

    fun getSettings(): Settings = store.load().also { settings = it }

    fun saveSettings(s: Settings) {
        validate(s)
        store.save(s)
        settings = s
    }

    /**
     * A snapshot of the published state. Never mutated after publication, and
     * always read together with the tunnel's own view of itself, so a
     * `status="connected"` can no longer be handed to the UI alongside a tunnel
     * that does not exist (T215).
     *
     * The reconciliation used to be a read-only lie detector: it returned
     * "connecting" while the published state stayed `connected` and
     * [connectedOnce] stayed set, so the next engine event re-asserted the green
     * badge over the same dead path. It now *revokes* the claim: the one-shot that
     * authorised "connected" is cleared, the correction is published once, and the
     * user is told the path went away underneath them rather than left on a
     * spinner (T2xx).
     */
    fun getState(): RuntimeState {
        val snapshot = runtime
        val dead = deadPathReason(snapshot.status) ?: return snapshot
        connectedOnce.set(false)
        vpnEstablished.set(false)
        engineAssertedConnected.set(false)
        setRuntime("error", dead, null, snapshot.endpoint)
        return runtime
    }

    /**
     * Why a published `connected` cannot be believed right now, or `null` when it
     * can. Every clause asks a component that owns the fact rather than trusting
     * this controller's memory of it.
     */
    internal fun deadPathReason(status: String): String? {
        if (status != "connected") return null
        if (!runner.isRunning()) {
            return "The engine process is gone — nothing is carrying this device's traffic any more."
        }
        if (settings.routingMode != "tun") return null
        if (!VpnTunnel.up) {
            return "The VPN tunnel dropped — Aether is connected but the device is no longer routed through it."
        }
        // The service still exists but has released its descriptor: `VpnTunnel` can
        // lag behind a hard teardown, and a live service is the only witness that
        // matters here.
        AetherVpnService.current?.let { service ->
            if (!service.isTunnelUp()) {
                return "The VPN tunnel closed — the device is no longer routed through Aether."
            }
        }
        return null
    }

    internal fun malformedEventCount(): Int = malformedEvents.get()

    fun isVpnPrepared(): Boolean {
        return VpnService.prepare(context) == null
    }

    internal fun rollbackStartup(reason: String): String {
        Log.e(TAG, "Rolling back session startup: $reason")
        emitLog("Rolling back session startup: $reason")

        try {
            context.stopService(Intent(context, EngineService::class.java))
        } catch (e: Exception) {
            Log.w(TAG, "Failed to stop EngineService during rollback: ${e.message}")
        }
        val vpnErr = stopVpnService()

        resetSessionFlags()

        val stopped = runner.stopAndWait(3000)
        val stillRunning = runner.isRunning()
        val problems = mutableListOf<String>()
        if (vpnErr != null) problems += vpnErr
        if (!stopped || stillRunning) {
            val alivePid = runner.pid()
            val warn = "Engine process pid=$alivePid still running after rollback timeout"
            Log.e(TAG, warn)
            emitLog(warn)
            problems += warn
        }
        val finalReason = if (problems.isEmpty()) reason else "$reason — ${problems.joinToString("; ")}"
        setRuntime("error", finalReason, null, runtime.endpoint)
        return finalReason
    }

    fun connect(s: Settings): String? {
        if (runner.isRunning()) {
            if (runner.getState() == SupervisorState.SCANNING) {
                if (!runner.stopAndWait(3000)) {
                    val err = "Previous engine process is still terminating; launch aborted"
                    setRuntime("error", err, null, null)
                    return err
                }
            }
            if (runner.isRunning()) {
                val err = "Aether is already running"
                setRuntime("error", err, null, null)
                return err
            }
        }
        validate(s)
        // The permission check runs *before* anything is persisted. Answering
        // `VPN_PERMISSION_REQUIRED` after the save used to leave a device with a
        // stored `routingMode=tun` and no session behind it, so the next launch
        // started in a mode it had never been granted and the consent sheet came
        // back on every connect.
        if (s.routingMode == "tun") {
            val prep = VpnService.prepare(context)
            if (prep != null) {
                return "VPN_PERMISSION_REQUIRED"
            }
        }
        store.save(s)
        settings = s
        resetSessionFlags()
        malformedEvents.set(0)
        // A tunnel left over from a previous attempt carries the *old* SOCKS port,
        // and AetherVpnService will not re-establish while a tun exists: make the
        // stale one go away and say so instead of quietly ignoring the new setting.
        if (vpnStarted.get() || VpnTunnel.up) {
            val stale = stopVpnService()
            if (stale != null) {
                setRuntime("error", stale, null, null)
                return stale
            }
        }

        setRuntime("connecting", "Scanning reachable routes", null, null)
        val err = runner.start(s)
        if (err != null) {
            setRuntime("error", err, null, null)
            return err
        }
        
        val svc = Intent(context, EngineService::class.java)
        try {
            context.startForegroundService(svc)
        } catch (e: Exception) {
            Log.e(TAG, "startForegroundService failed: ${e.message}", e)
            return rollbackStartup("Service start failed: ${e.message}")
        }
        
        setRuntime("connecting", "Scanning reachable routes", runner.pid(), null)
        // VPN (hev) starts once local SOCKS is listening — see maybeStartVpn().
        return null
    }

    /**
     * Standalone scan: starts engine in scan-only mode without VPN or foreground service.
     */
    fun scan(
        protocol: String,
        ipVersion: String,
        concurrency: Int,
        timeoutMs: Int,
        noize: String,
        runId: String = "",
    ): String? {
        // Recorded before anything can emit: the first `scan_start` must carry the id
        // the UI is filtering on.
        scanRunId = runId
        if (runner.isRunning()) {
            if (!runner.stopAndWait(3000)) {
                val err = "Previous engine process is still terminating; scan aborted"
                emitLog("scan error: $err")
                scanTerminalSent.set(true)
                emitScan(JSONObject().put("type", "scan_failed").put("message", err))
                return err
            }
            if (runner.isRunning()) {
                val err = "Engine could not be stopped for scan"
                emitLog("scan error: $err")
                scanTerminalSent.set(true)
                emitScan(JSONObject().put("type", "scan_failed").put("message", err))
                return err
            }
        }
        scanTerminalSent.set(false)
        val err = runner.startScan(protocol, ipVersion, concurrency, timeoutMs, noize)
        if (err != null) {
            emitLog("scan error: $err")
            scanTerminalSent.set(true)
            emitScan(JSONObject().put("type", "scan_failed").put("message", err))
            return err
        }
        return null
    }

    fun stopScan() {
        runner.stop()
    }

    /**
     * Tear the session down.
     *
     * @return `null` when everything that was up is now down, otherwise the
     *   actionable reason the caller must show. The old version returned Unit and
     *   then reported `disconnected`/"Ready" no matter what the VPN stop did
     *   (T206), so a still-running tunnel was announced as gone.
     */
    fun disconnect(): String? {
        if (!tearingDown.compareAndSet(false, true)) return null
        // Fail-closed ordering (T216): a stale engine must not be left holding the
        // SOCKS port the next connect() will ask the tunnel for.
        val engineStopped = runner.stopAndWait(3000)
        val engineStillUp = !engineStopped || runner.isRunning()
        try {
            context.stopService(Intent(context, EngineService::class.java))
        } catch (e: Exception) {
            Log.w(TAG, "Failed to stop EngineService during disconnect: ${e.message}")
        }
        val vpnErr = stopVpnService()
        resetSessionFlags()
        // Whatever the teardown found, this session was asked to stop, so the next
        // process has nothing to report. Leaving the ledger set would turn a
        // routine disconnect into an "unexpectedly ended" alarm on next launch.
        ledger.clearActive()

        val problems = mutableListOf<String>()
        if (vpnErr != null) problems += vpnErr
        if (engineStillUp) problems += "engine process pid=${runner.pid()} is still running"
        tearingDown.set(false)

        if (problems.isNotEmpty()) {
            val detail = "Could not fully stop Aether: ${problems.joinToString("; ")}"
            Log.e(TAG, detail)
            setRuntime("error", detail, null, runtime.endpoint)
            return detail
        }
        setRuntime("disconnected", "Ready", null, null)
        return null
    }

    fun testConnection(s: Settings): JSONObject {
        val proxy = "http://127.0.0.1:${s.httpPort}"
        val client = okhttp3.OkHttpClient.Builder()
            .proxy(
                java.net.Proxy(
                    java.net.Proxy.Type.HTTP,
                    java.net.InetSocketAddress("127.0.0.1", s.httpPort),
                ),
            )
            .callTimeout(java.time.Duration.ofSeconds(12))
            .build()
        val req = okhttp3.Request.Builder()
            .url("https://www.cloudflare.com/cdn-cgi/trace")
            .get()
            .build()
        // Timed across the whole proxied exchange — connect, TLS, response — from a
        // monotonic clock, so a wall-clock adjustment cannot change the number.
        val startedAt = android.os.SystemClock.elapsedRealtime()
        client.newCall(req).execute().use { resp ->
            if (!resp.isSuccessful) throw Exception("proxy test failed: HTTP ${resp.code}")
            val body = resp.body?.string().orEmpty()
            val latencyMs = android.os.SystemClock.elapsedRealtime() - startedAt
            val ip = body.lineSequence().firstOrNull { it.startsWith("ip=") }?.removePrefix("ip=")
                ?: "unknown"
            val loc = body.lineSequence().firstOrNull { it.startsWith("loc=") }?.removePrefix("loc=")
                ?: "?"
            // The round-trip time is a measured number, so it is returned as one.
            // It used to be folded into the prose (`... - ip=… loc=…`, no `ms` at
            // all) and the UI scraped it back out with `(\d+)\s*ms`, which never
            // matched the success line — the tile read "not measured" forever — and
            // *could* match a timeout digits inside a failure string, printing a
            // failure's 12000 ms as if it were a latency.
            return JSONObject()
                .put("detail", "OK via $proxy - ip=$ip loc=$loc")
                .put("latencyMs", latencyMs)
                .put("ip", ip)
                .put("loc", loc)
        }
    }

    fun validate(s: Settings) {
        validateSettings(s)
    }

    /**
     * One line of engine output.
     *
     * The lifecycle is driven exclusively by structured `AETHER_EVENT` JSON
     * ([EngineEvent]) — see T129. The prose this replaces asked whether a log line
     * contained "handshake successful", a sentence the engine has never printed, so
     * a healthy tunnel stayed "connecting" forever while the real
     * `{"type":"connected"}` event on the very same line was parsed, discarded and
     * left unreported. Nothing here infers state from wording any more.
     */
    private fun handleEngineLine(line: String) {
        emitLog(line)
        val ev = EngineEvent.parse(line)
        if (ev == null) {
            // An endpoint may still arrive as log prose; it only ever labels the
            // header, it never moves the state machine.
            parseEndpoint(line)?.let { setEndpoint(it) }
            return
        }
        when (ev) {
            is EngineEvent.Malformed -> {
                val count = malformedEvents.incrementAndGet()
                // Counted and visible on the log stream: the contract between the
                // engine and this shell is broken, and a dropped event used to be
                // indistinguishable from an event that never happened.
                reportStreamError(
                    "engine event rejected (#$count this session): ${ev.reason} — ${ev.raw.take(200)}",
                )
            }

            is EngineEvent.Unrecognised -> {
                val count = unknownEvents.incrementAndGet()
                Log.w(TAG, "unhandled engine event '${ev.type}' (#$count)")
                emit(
                    "session://log",
                    JSONObject().put("level", "warn")
                        .put("message", "unhandled engine event '${ev.type}' (#$count)"),
                )
            }

            is EngineEvent.Stage -> Unit

            is EngineEvent.IdentityReady -> Unit

            is EngineEvent.EndpointSelected -> {
                if (!runner.isScanMode() && ev.addr.isNotEmpty()) {
                    setEndpoint(ev.addr)
                    // The connect path emits no scan_done — close the live scan card
                    // once a gateway is chosen so it does not linger during the tunnel.
                    emitScan(
                        JSONObject().put("type", "scan_done")
                            .put("addr", ev.addr).put("rtt", "").put("protocol", ev.protocol),
                    )
                }
            }

            is EngineEvent.ProxyReady -> {
                socksSeen.set(true)
                maybeStartVpn()
            }

            is EngineEvent.TunnelReady,
            is EngineEvent.TunReady,
            -> {
                tunnelSeen.set(true)
                maybeStartVpn()
            }

            is EngineEvent.Connected -> {
                tunnelSeen.set(true)
                engineAssertedConnected.set(true)
                maybeStartVpn()
            }

            is EngineEvent.Failure -> {
                emitLog("engine error: ${ev.message}")
                if (!runner.isScanMode()) {
                    rollbackStartup(ev.message)
                } else {
                    scanTerminalSent.set(true)
                    emitScan(JSONObject().put("type", "scan_failed").put("message", ev.message))
                }
            }

            is EngineEvent.Scan -> {
                if (ev.type == "scan_done") scanTerminalSent.set(true)
                emitScanEvent(ev.payload)
            }
        }
        evaluateReadiness()
    }

    /** A visible, counted error on the log stream (level "error" by construction). */
    private fun reportStreamError(message: String) {
        Log.e(TAG, message)
        emit("session://log", JSONObject().put("level", "error").put("message", message))
    }

    /**
     * Fail-closed readiness (T129): the path counts as up when the engine said so
     * structurally, or when its local listeners are accepting *and* — for the
     * MASQUE family, where `proxy_ready` precedes the tunnel — the tunnel itself
     * reported ready. A full-device tunnel additionally waits for the tun.
     */
    private fun evaluateReadiness() {
        val s = settings
        val pathReady = when {
            engineAssertedConnected.get() -> true
            s.protocol.lowercase().startsWith("masque") -> socksSeen.get() && tunnelSeen.get()
            else -> socksSeen.get()
        }
        if (!pathReady) return
        if (s.routingMode == "tun" && !vpnEstablished.get()) return
        markConnected()
    }

    /** MASQUE-family protocols carry the user's traffic inside the QUIC tunnel. */
    private fun requiresTunnelPath(protocol: String): Boolean =
        protocol.lowercase().startsWith("masque")

    private fun maybeStartVpn() {
        if (settings.routingMode != "tun") return
        if (!socksSeen.get()) return
        // Wait until the tunnel path is actually up so early SOCKS accepts
        // do not blackhole the first wave of DNS/TCP from other apps.
        if (requiresTunnelPath(settings.protocol) && !tunnelSeen.get()) return
        if (!vpnStarted.compareAndSet(false, true)) return
        val port = settings.socksPort
        try {
            val vpn = Intent(context, AetherVpnService::class.java).apply {
                putExtra(AetherVpnService.EXTRA_SOCKS_PORT, port)
            }
            context.startForegroundService(vpn)
            Log.i(TAG, "started AetherVpnService socks=$port")
            emitLog("VPN: starting tun2socks -> 127.0.0.1:$port")
        } catch (e: Exception) {
            Log.e(TAG, "VPN start failed: ${e.message}", e)
            vpnStarted.set(false)
            rollbackStartup("VPN start failed: ${e.message}")
        }
    }

    /**
     * Ask [AetherVpnService] to tear its tunnel down.
     *
     * @return `null` when the stop was accepted, otherwise an actionable message.
     *   The swallow this replaces meant a background `startService` rejection —
     *   which Android answers with `IllegalStateException` — left the tun up while
     *   the session went on to report "disconnected"/"Ready" (T206).
     */
    internal fun stopVpnService(): String? {
        var refused: Throwable? = null
        val stop = Intent(context, AetherVpnService::class.java).apply {
            action = AetherVpnService.ACTION_STOP
        }
        try {
            // The cooperative stop is what actually closes the fd; `stopService`
            // alone can be answered by the system after the process is long gone.
            context.startService(stop)
            vpnStopPending.set(true)
        } catch (e: Exception) {
            refused = e
            Log.e(TAG, "VPN stop request failed: ${e.message}", e)
            if (e is IllegalStateException) {
                // API 26+ answers `startService` from a backgrounded app with
                // IllegalStateException. The stop must still reach a service that may
                // be carrying the device, so escalate — [AetherVpnService] answers an
                // ACTION_STOP by taking itself into the foreground first, which is what
                // makes `startForegroundService` legal on this path. The refusal is
                // still reported: an escalation is a request, not a confirmation.
                try {
                    context.startForegroundService(stop)
                } catch (e2: Exception) {
                    refused = e2
                    Log.e(TAG, "escalated VPN stop request also failed: ${e2.message}", e2)
                }
            }
        }
        try {
            context.stopService(Intent(context, AetherVpnService::class.java))
        } catch (e: Exception) {
            refused = refused ?: e
            Log.e(TAG, "VPN stopService failed: ${e.message}", e)
        }
        if (refused == null) return null
        vpnStopPending.set(false)
        // Ask the service rather than assume: it owns the descriptor.
        val stillUp = VpnTunnel.up || AetherVpnService.current?.isTunnelUp() == true
        val evidence = if (stillUp) {
            "the tunnel still reports itself up"
        } else {
            "whether the tunnel closed cannot be confirmed"
        }
        val detail = "VPN tunnel could not be stopped (${refused.message ?: refused.javaClass.simpleName}); " +
            "$evidence, so it may still be carrying this device's traffic. Open system Settings > " +
            "Network & internet > VPN and disconnect Aether Next, then force-stop the app."
        reportStreamError(detail)
        return detail
    }

    fun onVpnEstablished() {
        vpnEstablished.set(true)
        VpnTunnel.established(true, settings.socksPort)
        emitLog("VPN: tun2socks established")
        evaluateReadiness()
    }

    /**
     * The watchdog found the data path dead and is restarting the tunnel. The badge
     * comes down *now* — a tunnel that is being rebuilt is not one that is carrying
     * the user's traffic — and the revocation is what lets [markConnected] re-authorise
     * it if the restart succeeds.
     */
    fun onVpnRestartScheduled(attempt: Int) {
        connectedOnce.set(false)
        vpnEstablished.set(false)
        emitLog("VPN: data path unresponsive, supervised restart #$attempt")
        setRuntime("connecting", "Recovering the tunnel (attempt $attempt)", runtime.pid, runtime.endpoint)
    }

    /** The service confirmed the tun is closed; only now may the session say "Ready". */
    fun onVpnStopped() {
        VpnTunnel.established(false, -1)
        vpnEstablished.set(false)
        if (!vpnStopPending.compareAndSet(true, false)) return
        if (!runner.isRunning() && !tearingDown.get()) {
            setRuntime("disconnected", "Ready", null, null)
        }
    }

    fun onVpnFailed(message: String) {
        rollbackStartup("VPN failed: $message")
    }

    /**
     * Publish a crash. Reached from [AetherApp]'s uncaught-exception forwarder,
     * which is why it does not go through the WebView: the thread that crashed may
     * have been the one owning it.
     */
    fun reportCrash(reason: String) {
        resetSessionFlags()
        setRuntime("error", "App crashed: $reason", null, runtime.endpoint)
    }

    private fun parseEndpoint(line: String): String? {
        for (marker in listOf(
            "selected MASQUE gateway ",
            "selected WireGuard endpoint ",
            "using cloudflare edge ",
            "using forced peer ",
            "best gateway ",
            "best wg endpoint ",
        )) {
            val i = line.indexOf(marker)
            if (i >= 0) {
                val rest = line.substring(i + marker.length)
                val token = rest.split(Regex("\\s+")).firstOrNull()
                    ?.trim('(', ')', ',')
                    ?: continue
                if (token.isNotEmpty()) return token
            }
        }
        return null
    }

    private fun markConnected() {
        if (!connectedOnce.compareAndSet(false, true)) return
        val detail = when (settings.routingMode) {
            "tun" -> "VPN active (full device)"
            "system-proxy" -> "App proxy active"
            else -> "Proxy only active"
        }
        ledger.markActive()
        setRuntime("connected", detail, runner.pid(), runtime.endpoint)
    }

    /** Publish a whole new snapshot; the old one is never touched again. */
    private fun setRuntime(
        status: String,
        detail: String,
        pid: Int?,
        endpoint: String?,
    ) = synchronized(stateLock) {
        val previous = runtime
        val next = RuntimeState(
            status = status,
            detail = detail,
            pid = pid,
            endpoint = when {
                status == "disconnected" -> null
                endpoint != null -> endpoint
                status == "error" -> previous.endpoint
                else -> previous.endpoint
            },
        )
        runtime = next
        emit("session://state", next.toJson())
    }

    /** Endpoint label only — it never changes [status]. */
    private fun setEndpoint(endpoint: String) = synchronized(stateLock) {
        val next = runtime.copy(endpoint = endpoint)
        runtime = next
        emit("session://state", next.toJson())
    }

    /**
     * Re-shape an engine AETHER_EVENT scan payload into the webview's scan://event
     * contract. The engine emits snake_case `rtt_ms`; the UI expects `rttMs`.
     */
    private fun emitScanEvent(src: JSONObject) {
        val type = src.optString("type")
        val out = JSONObject().put("type", type)
        when (type) {
            "scan_start" -> out
                .put("mode", src.optString("mode"))
                .put("total", src.optLong("total"))
                .put("concurrency", src.optLong("concurrency"))
            "scan_progress" -> out
                .put("scanned", src.optLong("scanned"))
                .put("total", src.optLong("total"))
                .put("working", src.optLong("working"))
            "scan_hit" -> out
                .put("addr", src.optString("addr"))
                .put("rtt", src.optString("rtt"))
                .put("rttMs", src.optDouble("rtt_ms", 0.0))
                .put("protocol", src.optString("protocol"))
            "scan_done" -> out
                .put("addr", src.optString("addr"))
                .put("rtt", src.optString("rtt"))
                .put("protocol", src.optString("protocol"))
        }
        emitScan(out)
    }

    /**
     * The one exit for a scan event: it stamps the run id (see [scanRunId]) so the
     * UI can tell a live run's events from a cancelled one's.
     */
    private fun emitScan(payload: JSONObject) {
        val id = scanRunId
        if (id.isNotEmpty() && payload.isNull("runId")) payload.put("runId", id)
        emit("scan://event", payload)
    }

    fun emitLog(message: String) {
        val level = logLevelOf(message)
        emitAt(level, message)
    }

    /** A warning that must not be classified out of existence by its wording. */
    fun emitWarn(message: String) = emitAt("warn", message)

    internal fun logLevelOf(message: String): String = when {
        message.lowercase().contains("error") || message.lowercase().contains("failed") -> "error"
        message.lowercase().contains("warn") || message.lowercase().contains("[-]") -> "warn"
        else -> "info"
    }

    /**
     * Publish one log line, batching the chatty ones (T2xx).
     *
     * `RUST_LOG=info` during a scan is hundreds of lines a second, and each used to
     * be its own `evaluateJavascript` post on the main thread *and* its own copy of
     * the web layer's log array — the flood was the UI, not the engine. Info lines
     * are therefore queued and flushed as a single `session://logs` event every
     * [LOG_FLUSH_INTERVAL_MS] or every [LOG_BATCH_MAX_LINES] lines, whichever comes
     * first.
     *
     * `warn` and `error` are never queued: they flush the pending batch (so ordering
     * survives) and go out on their own, immediately. Dropping the oldest lines of an
     * info burst is reported rather than silent, because a log that quietly loses its
     * middle is worse than no log.
     */
    private fun emitAt(level: String, message: String) {
        if (level != "info") {
            flushLogs()
            emit("session://log", JSONObject().put("level", level).put("message", message))
            return
        }
        val full: Boolean
        synchronized(logLock) {
            if (logBatch.size >= LOG_HARD_CAP) {
                // Bounded: the burst is reported as dropped, never allowed to grow
                // the queue without limit.
                logDropped.incrementAndGet()
                full = false
            } else {
                logBatch.add(JSONObject().put("level", level).put("message", message))
                full = logBatch.size >= LOG_BATCH_MAX_LINES
            }
        }
        if (full) flushLogs() else scheduleLogFlush()
    }

    private fun scheduleLogFlush() {
        if (logFlushScheduled.getAndSet(true)) return
        logScheduler.schedule({ flushLogs() }, LOG_FLUSH_INTERVAL_MS, java.util.concurrent.TimeUnit.MILLISECONDS)
    }

    /** Emit whatever info lines are queued. Safe from any thread, and idempotent. */
    internal fun flushLogs() {
        var batch: List<JSONObject>
        val dropped: Int
        synchronized(logLock) {
            logFlushScheduled.set(false)
            if (logBatch.isEmpty()) return
            batch = logBatch.toList()
            logBatch.clear()
            dropped = logDropped.getAndSet(0)
        }
        if (dropped > 0) {
            batch += JSONObject().put("level", "warn")
                .put("message", "$dropped log lines were dropped during this burst")
        }
        if (batch.size == 1) {
            emit("session://log", batch[0])
        } else {
            emit(
                "session://logs",
                JSONObject().put("entries", org.json.JSONArray(batch)),
            )
        }
    }

    companion object {
        private const val TAG = "SessionController"

        /** The UI's own caps for the custom noise profile; a save beyond them is junk input. */
        const val NOIZE_JC_MAX = 64
        const val NOIZE_SIZE_MAX = 2048

        /** Log coalescing cadence and burst bounds (T2xx). */
        const val LOG_FLUSH_INTERVAL_MS = 40L
        const val LOG_BATCH_MAX_LINES = 64
        const val LOG_HARD_CAP = 2_000

        @Volatile
        private var instance: SessionController? = null

        fun validateSettings(s: Settings) {
            val validProtocols = setOf("masque", "masque-h2", "masque-h3", "wireguard", "wg", "gool")
            if (s.protocol.lowercase() !in validProtocols) {
                throw SettingRejected("protocol", "Invalid protocol '${s.protocol}'. Allowed: $validProtocols")
            }
            val validTransports = setOf("h2", "h3")
            if (s.transport.lowercase() !in validTransports) {
                throw SettingRejected("transport", "Invalid transport '${s.transport}'. Allowed: $validTransports")
            }
            val validScanModes = setOf("balanced", "fast", "deep", "turbo", "stealth", "thorough", "ironclad")
            if (s.scanMode.lowercase() !in validScanModes) {
                throw SettingRejected("scanMode", "Invalid scanMode '${s.scanMode}'. Allowed: $validScanModes")
            }
            val validIpVersions = setOf("v4", "v6", "dual", "both")
            if (s.ipVersion.lowercase() !in validIpVersions) {
                throw SettingRejected("ipVersion", "Invalid ipVersion '${s.ipVersion}'. Allowed: $validIpVersions")
            }
            val validRoutingModes = setOf("tun", "proxy-only", "system-proxy")
            if (s.routingMode.lowercase() !in validRoutingModes) {
                throw SettingRejected("routingMode", "Invalid routingMode '${s.routingMode}'. Allowed: $validRoutingModes")
            }
            val validNoize = NoizeProfiles.appValues
            if (s.noize.lowercase() !in validNoize) {
                throw SettingRejected(
                    "noize",
                    "Invalid noize mode '${s.noize}'. Allowed: $validNoize — the engine " +
                        "understands ${NoizeProfiles.engineValues.joinToString("|")}, and this shell " +
                        "translates rather than silently downgrading.",
                )
            }
            if (s.httpPort !in 1024..65535) {
                throw SettingRejected("httpPort", "HTTP port must be 1024-65535 (got ${s.httpPort})")
            }
            if (s.socksPort !in 1024..65535) {
                throw SettingRejected("socksPort", "SOCKS5 port must be 1024-65535 (got ${s.socksPort})")
            }
            if (s.socksPort == s.httpPort) {
                throw SettingRejected("httpPort", "HTTP and SOCKS5 ports must differ")
            }
            if (s.quicInitialFragSize !in 16..512) {
                throw SettingRejected("quicInitialFragSize", "quicInitialFragSize must be between 16 and 512")
            }
            // One message for three inputs told the user nothing about which one.
            // Bounded on both sides: the UI caps these at 64 / 2048 bytes, and a
            // validation that only checked `>= 0` accepted 999999 junk packets per
            // probe and handed them to the engine as if the user had asked for them.
            if (s.noizeJc !in 0..NOIZE_JC_MAX) {
                throw SettingRejected("noizeJc", "noizeJc must be 0-$NOIZE_JC_MAX (got ${s.noizeJc})")
            }
            if (s.noizeJmin !in 0..NOIZE_SIZE_MAX) {
                throw SettingRejected("noizeJmin", "noizeJmin must be 0-$NOIZE_SIZE_MAX (got ${s.noizeJmin})")
            }
            if (s.noizeJmax !in 0..NOIZE_SIZE_MAX) {
                throw SettingRejected("noizeJmax", "noizeJmax must be 0-$NOIZE_SIZE_MAX (got ${s.noizeJmax})")
            }
            if (s.noizeJmax < s.noizeJmin) {
                throw SettingRejected("noizeJmax", "noizeJmax (${s.noizeJmax}) must be >= noizeJmin (${s.noizeJmin})")
            }
        }

        fun get(context: Context, emit: (String, JSONObject) -> Unit): SessionController {
            return synchronized(this) {
                val existing = instance
                if (existing != null) {
                    existing.setEmitter(emit)
                    existing
                } else {
                    SessionController(context.applicationContext, emit).also { instance = it }
                }
            }
        }

        fun getOrNull(): SessionController? = instance
    }
}

/**
 * The process-wide answer to "is there a tun right now, and on which SOCKS port?".
 *
 * [AetherVpnService] owns the descriptor and publishes here when it opens or closes
 * it; [SessionController] reads it so it can *check* a teardown instead of
 * announcing one (T206), and so a published `connected` state can be reconciled
 * against a tunnel that vanished underneath it (T215). `@Volatile` because the
 * writer is the VPN worker thread and the readers are the main and bridge threads.
 */
internal object VpnTunnel {
    @Volatile
    var up: Boolean = false
        private set

    @Volatile
    var socksPort: Int = -1
        private set

    fun established(isUp: Boolean, port: Int) {
        socksPort = port
        up = isUp
    }
}
