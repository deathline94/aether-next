package app.aethernext

import android.webkit.JavascriptInterface
import org.json.JSONObject

/**
 * WebView bridge exposing the same command surface as Tauri desktop invoke().
 */
class AetherBridge(
    private val activity: MainActivity,
    private val session: SessionController,
) {
    @JavascriptInterface
    fun invoke(cmd: String, argsJson: String): String {
        return try {
            val args = if (argsJson.isBlank()) JSONObject() else JSONObject(argsJson)
            val data: Any? = when (cmd) {
                "get_settings" -> handleGetSettings()
                "save_settings" -> handleSaveSettings(args)
                "get_state" -> session.getState().toJson()
                "is_admin" -> session.isVpnPrepared()
                "connect" -> handleConnect(args)
                "disconnect" -> handleDisconnect()
                "scan" -> handleScan(args)
                "stop_scan" -> handleStopScan()
                "test_connection" -> handleTestConnection(args)
                "app_info" -> handleAppInfo()
                else -> throw IllegalArgumentException("unknown command $cmd")
            }
            ok(data)
        } catch (e: Exception) {
            err(e.message ?: e.toString())
        }
    }

    internal fun handleGetSettings(): Any =
        session.getSettings().toJson()

    internal fun handleSaveSettings(args: JSONObject): Any {
        val s = Settings.fromJson(args.getJSONObject("settings"))
        session.saveSettings(s)
        return JSONObject.NULL
    }

    internal fun handleConnect(args: JSONObject): Any {
        val s = if (args.has("settings")) {
            Settings.fromJson(args.getJSONObject("settings"))
        } else {
            session.getSettings()
        }
        val err = session.connect(s)
        return when {
            err == "VPN_PERMISSION_REQUIRED" -> {
                activity.requestVpnPermission()
                // Permission pending - not a hard failure
                JSONObject.NULL
            }
            err != null -> throw IllegalStateException(err)
            else -> JSONObject.NULL
        }
    }

    internal fun handleDisconnect(): Any {
        session.disconnect()
        return JSONObject.NULL
    }

    internal fun handleScan(args: JSONObject): Any {
        val protocol = args.optString("protocol", "masque-h3")
        val ipVersion = args.optString("ipVersion", "v4")
        val concurrency = args.optInt("concurrency", 250).coerceIn(1, 2000)
        val rawTimeout = args.optInt("timeoutMs", 6000).coerceIn(3000, 30000)
        val timeoutMs = if (protocol.contains("h3", ignoreCase = true) || protocol.equals("masque", ignoreCase = true)) {
            Math.max(6000, rawTimeout)
        } else {
            rawTimeout
        }
        val noize = args.optString("noize", "off")
        val err = session.scan(protocol, ipVersion, concurrency, timeoutMs, noize)
        if (err != null) throw IllegalStateException(err)
        return JSONObject.NULL
    }

    internal fun handleStopScan(): Any {
        session.stopScan()
        return JSONObject.NULL
    }

    internal fun handleTestConnection(args: JSONObject): Any {
        val s = if (args.has("settings")) {
            Settings.fromJson(args.getJSONObject("settings"))
        } else {
            session.getSettings()
        }
        return session.testConnection(s)
    }

    internal fun handleAppInfo(): Any =
        JSONObject()
            .put("name", "Aether Next")
            .put("version", BuildConfig.VERSION_NAME)
            .put("author", "deathline94")
            .put("engine", "deathline94/aether-next")
            .put("platform", "android")

    private fun ok(data: Any?): String {
        val o = JSONObject().put("ok", true)
        when (data) {
            null, JSONObject.NULL -> o.put("data", JSONObject.NULL)
            is JSONObject -> o.put("data", data)
            is Boolean -> o.put("data", data)
            is Number -> o.put("data", data)
            is String -> o.put("data", data)
            else -> o.put("data", data.toString())
        }
        return o.toString()
    }

    private fun err(message: String): String =
        JSONObject().put("ok", false).put("error", message).toString()
}
