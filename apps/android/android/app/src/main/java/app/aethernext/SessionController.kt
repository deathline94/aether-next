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
    private var settings = store.load()

    private val runner = EngineRunner(
        context = context,
        onLine = { line -> handleEngineLine(line) },
        onExit = { code ->
            connectedOnce.set(false)
            socksSeen.set(false)
            tunnelSeen.set(false)
            vpnStarted.set(false)
            setRuntime(
                "disconnected",
                if (code == 0 || code == null) "Engine stopped" else "Engine exited ($code)",
                null,
                null,
            )
            context.stopService(Intent(context, EngineService::class.java))
            stopVpnService()
        },
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

    fun connect(s: Settings): String? {
        if (runner.isRunning()) return "Aether is already running"
        validate(s)
        store.save(s)
        settings = s
        connectedOnce.set(false)
        socksSeen.set(false)
        tunnelSeen.set(false)
        vpnStarted.set(false)

        if (s.routingMode == "tun") {
            val prep = VpnService.prepare(context)
            if (prep != null) {
                return "VPN_PERMISSION_REQUIRED"
            }
        }

        val svc = Intent(context, EngineService::class.java)
        context.startForegroundService(svc)

        setRuntime("connecting", "Scanning reachable routes", null, null)
        val err = runner.start(s)
        if (err != null) {
            setRuntime("error", err, null, null)
            context.stopService(svc)
            return err
        }
        setRuntime("connecting", "Scanning reachable routes", runner.pid(), null)
        // VPN (hev) starts once local SOCKS is listening — see maybeStartVpn().
        return null
    }

    fun disconnect() {
        runner.stop()
        context.stopService(Intent(context, EngineService::class.java))
        stopVpnService()
        connectedOnce.set(false)
        socksSeen.set(false)
        tunnelSeen.set(false)
        vpnStarted.set(false)
        setRuntime("disconnected", "Ready", null, null)
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

    private fun validate(s: Settings) {
        if (s.socksPort < 1024 || s.httpPort < 1024) {
            throw IllegalArgumentException("Ports must be 1024-65535")
        }
        if (s.socksPort == s.httpPort) {
            throw IllegalArgumentException("HTTP and SOCKS5 ports must differ")
        }
    }

    private fun handleEngineLine(line: String) {
        emitLog(line)
        val idx = line.indexOf("AETHER_EVENT ")
        if (idx >= 0) {
            try {
                val json = JSONObject(line.substring(idx + "AETHER_EVENT ".length).trim())
                when (json.optString("type")) {
                    "endpoint_selected" -> {
                        runtime.endpoint = json.optString("addr").ifEmpty { null }
                        emitState()
                    }
                    "proxy_ready" -> {
                        socksSeen.set(true)
                        maybeStartVpn()
                    }
                    "tunnel_ready", "tun_ready", "connected" -> {
                        socksSeen.set(true)
                        tunnelSeen.set(true)
                        maybeStartVpn()
                    }
                    "error" -> emitLog("engine error: ${json.optString("message")}")
                }
            } catch (_: Exception) {
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
        if (ready) markConnected()
    }

    private fun maybeStartVpn() {
        if (settings.routingMode != "tun") return
        if (!socksSeen.get()) return
        if (!vpnStarted.compareAndSet(false, true)) return
        try {
            val vpn = Intent(context, AetherVpnService::class.java).apply {
                putExtra(AetherVpnService.EXTRA_SOCKS_PORT, settings.socksPort)
            }
            context.startForegroundService(vpn)
            Log.i(TAG, "started AetherVpnService socks=${settings.socksPort}")
            emitLog("VPN: starting tun2socks -> 127.0.0.1:${settings.socksPort}")
        } catch (e: Exception) {
            vpnStarted.set(false)
            Log.e(TAG, "VPN start failed: ${e.message}", e)
            emitLog("VPN start failed: ${e.message}")
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

    private fun emitLog(message: String) {
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
