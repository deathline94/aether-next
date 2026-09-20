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
    private var emit: (event: String, payload: JSONObject) -> Unit,
    runnerFactory: ((onLine: (String) -> Unit, onExit: (Int?, Boolean) -> Unit) -> EngineRunner)? = null,
) {
    fun setEmitter(fn: (event: String, payload: JSONObject) -> Unit) {
        emit = fn
    }

    private val store = SettingsStore(context)
    private val runtime = RuntimeState()
    private val connectedOnce = AtomicBoolean(false)
    private val socksSeen = AtomicBoolean(false)
    private val tunnelSeen = AtomicBoolean(false)
    private val vpnStarted = AtomicBoolean(false)
    private val vpnEstablished = AtomicBoolean(false)
    private val tearingDown = AtomicBoolean(false)
    private var settings = store.load()

    private fun handleExit(code: Int?, isScan: Boolean) {
        if (isScan) {
            // Ensure the scanner UI never sticks "active" if the engine exits mid-scan.
            emit(
                "scan://event",
                JSONObject().put("type", "scan_done").put("addr", "").put("rtt", "").put("protocol", ""),
            )
            if (runtime.status != "connected") {
                setRuntime("disconnected", "Ready", null, null)
            }
            return
        }
        val wasConnected = connectedOnce.get()
        connectedOnce.set(false)
        socksSeen.set(false)
        tunnelSeen.set(false)
        vpnStarted.set(false)
        vpnEstablished.set(false)
        val isError = code != null && code != 0 && !wasConnected
        setRuntime(
            if (isError) "error" else "disconnected",
            if (isError) "Could not find a working gateway"
            else if (code == 0 || code == null) "Engine stopped"
            else "Engine exited ($code)",
            null,
            null,
        )
        // Ensure the scanner UI never sticks "active" if the engine exits mid-scan.
        emit(
            "scan://event",
            JSONObject().put("type", "scan_done").put("addr", "").put("rtt", "").put("protocol", ""),
        )
        context.stopService(Intent(context, EngineService::class.java))
        stopVpnService()
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

    fun getState(): RuntimeState = runtime

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
        stopVpnService()

        connectedOnce.set(false)
        socksSeen.set(false)
        tunnelSeen.set(false)
        vpnStarted.set(false)
        vpnEstablished.set(false)

        val stopped = runner.stopAndWait(3000)
        val stillRunning = runner.isRunning()
        val finalReason = if (!stopped || stillRunning) {
            val alivePid = runner.pid()
            val warn = "$reason (Engine process pid=$alivePid still running after rollback timeout)"
            Log.e(TAG, warn)
            emitLog(warn)
            warn
        } else {
            reason
        }

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
        store.save(s)
        settings = s
        connectedOnce.set(false)
        socksSeen.set(false)
        tunnelSeen.set(false)
        vpnStarted.set(false)
        vpnEstablished.set(false)

        if (s.routingMode == "tun") {
            val prep = VpnService.prepare(context)
            if (prep != null) {
                return "VPN_PERMISSION_REQUIRED"
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
    ): String? {
        if (runner.isRunning()) {
            if (!runner.stopAndWait(3000)) {
                val err = "Previous engine process is still terminating; scan aborted"
                emitLog("scan error: $err")
                emit("scan://event", JSONObject().put("type", "scan_failed").put("message", err))
                return err
            }
            if (runner.isRunning()) {
                val err = "Engine could not be stopped for scan"
                emitLog("scan error: $err")
                emit("scan://event", JSONObject().put("type", "scan_failed").put("message", err))
                return err
            }
        }
        val err = runner.startScan(protocol, ipVersion, concurrency, timeoutMs, noize)
        if (err != null) {
            emitLog("scan error: $err")
            emit("scan://event", JSONObject().put("type", "scan_failed").put("message", err))
            return err
        }
        return null
    }

    fun stopScan() {
        runner.stop()
    }

    fun disconnect() {
        if (!tearingDown.compareAndSet(false, true)) return
        runner.stopAndWait(3000)
        context.stopService(Intent(context, EngineService::class.java))
        if (vpnStarted.get()) {
            stopVpnService()
        }
        connectedOnce.set(false)
        socksSeen.set(false)
        tunnelSeen.set(false)
        vpnStarted.set(false)
        vpnEstablished.set(false)
        setRuntime("disconnected", "Ready", null, null)
        tearingDown.set(false)
    }

    fun testConnection(s: Settings): String {
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
        client.newCall(req).execute().use { resp ->
            if (!resp.isSuccessful) throw Exception("proxy test failed: HTTP ${resp.code}")
            val body = resp.body?.string().orEmpty()
            val ip = body.lineSequence().firstOrNull { it.startsWith("ip=") }?.removePrefix("ip=")
                ?: "unknown"
            val loc = body.lineSequence().firstOrNull { it.startsWith("loc=") }?.removePrefix("loc=")
                ?: "?"
            return "OK via $proxy - ip=$ip loc=$loc"
        }
    }

    fun validate(s: Settings) {
        validateSettings(s)
    }

    private fun handleEngineLine(line: String) {
        emitLog(line)
        val idx = line.indexOf("AETHER_EVENT ")
        if (idx >= 0) {
            try {
                val json = JSONObject(line.substring(idx + "AETHER_EVENT ".length).trim())
                when (json.optString("type")) {
                    "endpoint_selected" -> {
                        if (!runner.isScanMode()) {
                            runtime.endpoint = json.optString("addr").ifEmpty { null }
                            emitState()
                            // The connect path emits no scan_done — close the live scan card
                            // once a gateway is chosen so it does not linger during the tunnel.
                            emit(
                                "scan://event",
                                JSONObject().put("type", "scan_done")
                                    .put("addr", json.optString("addr")).put("rtt", "").put("protocol", ""),
                            )
                        }
                    }
                    "proxy_ready" -> {
                        socksSeen.set(true)
                        maybeStartVpn()
                    }
                    "tunnel_ready", "tun_ready", "connected" -> {
                        tunnelSeen.set(true)
                        maybeStartVpn()
                    }
                    "error" -> {
                        val msg = json.optString("message", "Connection failed")
                        emitLog("engine error: $msg")
                        if (!runner.isScanMode()) {
                            rollbackStartup(msg)
                        } else {
                            emit("scan://event", JSONObject().put("type", "scan_failed").put("message", msg))
                        }
                    }
                    // Forward structured scan telemetry to the webview (scan://event),
                    // mirroring the desktop Tauri bridge. The UI consumes these instead
                    // of regex-parsing log lines.
                    "scan_start", "scan_progress", "scan_hit", "scan_done" -> emitScanEvent(json)
                }
            } catch (_: Exception) {
            }
        }
        if (line.contains("[-] session failed:")) {
            val msg = line.substringAfter("[-] session failed:").trim()
            if (!runner.isScanMode()) {
                rollbackStartup(msg)
            } else {
                emit("scan://event", JSONObject().put("type", "scan_failed").put("message", msg))
            }
        }
        if (line.contains("socks5 server listening") || line.contains("http proxy listening")) {
            socksSeen.set(true)
            maybeStartVpn()
        }
        if (
            line.contains("connect-ip status: 200") ||
            line.contains("handshake successful") ||
            line.contains("[tun] bridge active") ||
            line.contains("quic handshake established")
        ) {
            tunnelSeen.set(true)
            maybeStartVpn()
        }
        parseEndpoint(line)?.let {
            runtime.endpoint = it
            emitState()
        }

        val ready = if (settings.protocol == "masque") {
            socksSeen.get() && tunnelSeen.get()
        } else {
            socksSeen.get() || tunnelSeen.get()
        }
        if (ready && (settings.routingMode != "tun" || vpnEstablished.get())) markConnected()
    }

    private fun maybeStartVpn() {
        if (settings.routingMode != "tun") return
        if (!socksSeen.get()) return
        // Wait until the tunnel path is actually up so early SOCKS accepts
        // do not blackhole the first wave of DNS/TCP from other apps.
        if (settings.protocol == "masque" && !tunnelSeen.get()) return
        if (!vpnStarted.compareAndSet(false, true)) return
        try {
            val vpn = Intent(context, AetherVpnService::class.java).apply {
                putExtra(AetherVpnService.EXTRA_SOCKS_PORT, settings.socksPort)
            }
            context.startForegroundService(vpn)
            Log.i(TAG, "started AetherVpnService socks=${settings.socksPort}")
            emitLog("VPN: starting tun2socks -> 127.0.0.1:${settings.socksPort}")
        } catch (e: Exception) {
            Log.e(TAG, "VPN start failed: ${e.message}", e)
            rollbackStartup("VPN start failed: ${e.message}")
        }
    }

    private fun stopVpnService() {
        try {
            val stop = Intent(context, AetherVpnService::class.java).apply {
                action = AetherVpnService.ACTION_STOP
            }
            context.startService(stop)
        } catch (_: Exception) {
        }
        context.stopService(Intent(context, AetherVpnService::class.java))
    }

    fun onVpnEstablished() {
        vpnEstablished.set(true)
        emitLog("VPN: tun2socks established")
        val ready = socksSeen.get() && (settings.protocol != "masque" || tunnelSeen.get())
        if (ready) markConnected()
    }

    fun onVpnFailed(message: String) {
        rollbackStartup("VPN failed: $message")
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
        setRuntime("connected", detail, runner.pid(), runtime.endpoint)
    }

    private fun setRuntime(
        status: String,
        detail: String,
        pid: Int?,
        endpoint: String?,
    ) {
        runtime.status = status
        runtime.detail = detail
        runtime.pid = pid
        if (endpoint != null) runtime.endpoint = endpoint
        if (status == "disconnected" || status == "error") {
            if (status == "disconnected") runtime.endpoint = null
        }
        emitState()
    }

    private fun emitState() {
        emit("session://state", runtime.toJson())
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
        emit("scan://event", out)
    }

    fun emitLog(message: String) {
        val lower = message.lowercase()
        val level = when {
            lower.contains("error") || lower.contains("failed") -> "error"
            lower.contains("warn") || lower.contains("[-]") -> "warn"
            else -> "info"
        }
        emit(
            "session://log",
            JSONObject().put("level", level).put("message", message),
        )
    }

    companion object {
        private const val TAG = "SessionController"

        @Volatile
        private var instance: SessionController? = null

        fun validateSettings(s: Settings) {
            val validProtocols = setOf("masque", "masque-h2", "masque-h3", "wireguard", "wg", "gool")
            if (s.protocol.lowercase() !in validProtocols) {
                throw IllegalArgumentException("Invalid protocol '${s.protocol}'. Allowed: $validProtocols")
            }
            val validTransports = setOf("h2", "h3")
            if (s.transport.lowercase() !in validTransports) {
                throw IllegalArgumentException("Invalid transport '${s.transport}'. Allowed: $validTransports")
            }
            val validPresets = setOf("warp", "gool")
            if (s.endpointPreset.lowercase() !in validPresets) {
                throw IllegalArgumentException("Invalid endpointPreset '${s.endpointPreset}'. Allowed: $validPresets")
            }
            val validScanModes = setOf("balanced", "fast", "deep", "turbo", "stealth", "thorough", "ironclad")
            if (s.scanMode.lowercase() !in validScanModes) {
                throw IllegalArgumentException("Invalid scanMode '${s.scanMode}'. Allowed: $validScanModes")
            }
            val validIpVersions = setOf("v4", "v6", "dual", "both")
            if (s.ipVersion.lowercase() !in validIpVersions) {
                throw IllegalArgumentException("Invalid ipVersion '${s.ipVersion}'. Allowed: $validIpVersions")
            }
            val validRoutingModes = setOf("tun", "proxy-only", "system-proxy")
            if (s.routingMode.lowercase() !in validRoutingModes) {
                throw IllegalArgumentException("Invalid routingMode '${s.routingMode}'. Allowed: $validRoutingModes")
            }
            val validNoize = setOf("off", "on", "random", "m1", "m2", "light", "medium", "high", "max", "custom")
            if (s.noize.lowercase() !in validNoize) {
                throw IllegalArgumentException("Invalid noize mode '${s.noize}'. Allowed: $validNoize")
            }
            if (s.socksPort !in 1024..65535 || s.httpPort !in 1024..65535) {
                throw IllegalArgumentException("Ports must be 1024-65535")
            }
            if (s.socksPort == s.httpPort) {
                throw IllegalArgumentException("HTTP and SOCKS5 ports must differ")
            }
            if (s.quicInitialFragSize !in 16..512) {
                throw IllegalArgumentException("quicInitialFragSize must be between 16 and 512")
            }
            if (s.noizeJc < 0 || s.noizeJmin < 0 || s.noizeJmax < s.noizeJmin) {
                throw IllegalArgumentException("Invalid noize jitter bounds")
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
