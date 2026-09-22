package app.aethernext

import android.util.Log
import android.webkit.JavascriptInterface
import org.json.JSONException
import org.json.JSONObject

/**
 * WebView bridge exposing the same command surface as Tauri desktop invoke().
 *
 * [originTrusted] is the T219 gate. A `JavascriptInterface` is attached to the
 * WebView, not to the page that was supposed to be in it: anything that can make
 * this WebView show another document — a redirect, a failed load that fell back to
 * the generated error page, a `data:`/`about:` navigation — inherits the object
 * and with it `connect`, `disconnect`, `save_settings` and the engine's config.
 * Every call therefore re-checks that the document actually loaded is one this APK
 * shipped, using the URL captured on the UI thread in `onPageStarted`.
 */
class AetherBridge(
    private val activity: MainActivity,
    private val session: SessionController,
    private val originTrusted: () -> Boolean = { activity.isBridgeOriginTrusted() },
) {
    @JavascriptInterface
    fun invoke(cmd: String, argsJson: String): String {
        val trusted = try {
            originTrusted()
        } catch (e: Exception) {
            Log.w(TAG, "origin check threw, treating the caller as untrusted: ${e.message}")
            false
        }
        if (!trusted) {
            Log.e(TAG, "bridge call '$cmd' rejected: loaded page is not the packaged UI")
            return bridgeErr(
                "permission_denied",
                "Bridge call '$cmd' rejected: the loaded page is not the packaged Aether UI.",
                null,
            )
        }
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
                else -> throw BridgeError("unknown_command", "unknown command $cmd")
            }
            bridgeOk(data)
        } catch (e: SettingRejected) {
            bridgeErr("validation", e.message ?: "invalid setting", e.field)
        } catch (e: BridgeError) {
            bridgeErr(e.code, e.detail, e.field)
        } catch (e: JSONException) {
            // A malformed `settings` payload is a different conversation from a
            // failed connect: the caller sent something this side cannot parse.
            bridgeErr("encode", e.message ?: e.toString(), null)
        } catch (e: Exception) {
            bridgeErr("internal", e.message ?: e.toString(), null)
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
            err != null -> throw BridgeError("connect_failed", err)
            else -> JSONObject.NULL
        }
    }

    internal fun handleDisconnect(): Any {
        // T206: "I asked the tunnel to stop" is not "the tunnel stopped". The
        // message says what is still up and what to do about it, and it travels as
        // a coded rejection so the UI can show it instead of a green "Ready".
        val err = session.disconnect()
        if (err != null) throw BridgeError("stop_failed", err)
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
        if (err != null) throw BridgeError("scan_failed", err)
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

    companion object {
        private const val TAG = "AetherBridge"
    }
}
