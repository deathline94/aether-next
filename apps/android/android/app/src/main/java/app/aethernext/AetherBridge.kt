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
                "get_settings" -> session.getSettings().toJson()
                "save_settings" -> {
                    val s = Settings.fromJson(args.getJSONObject("settings"))
                    session.saveSettings(s)
                    JSONObject.NULL
                }
                "get_state" -> session.getState().toJson()
                "is_admin" -> session.isVpnPrepared()
                "connect" -> {
                    val s = if (args.has("settings")) {
                        Settings.fromJson(args.getJSONObject("settings"))
                    } else {
                        session.getSettings()
                    }
                    val err = session.connect(s)
                    when {
                        err == "VPN_PERMISSION_REQUIRED" -> {
                            activity.requestVpnPermission()
                            // Permission pending - not a hard failure
                            JSONObject.NULL
                        }
                        err != null -> throw IllegalStateException(err)
                        else -> JSONObject.NULL
                    }
                }
                "disconnect" -> {
                    session.disconnect()
                    JSONObject.NULL
                }
                "test_connection" -> {
                    val s = if (args.has("settings")) {
                        Settings.fromJson(args.getJSONObject("settings"))
                    } else {
                        session.getSettings()
                    }
                    session.testConnection(s)
                }
                "app_info" -> JSONObject()
                    .put("name", "Aether Next")
                    .put("version", BuildConfig.VERSION_NAME)
                    .put("author", "deathline94")
                    .put("engine", "deathline94/aether-next")
                    .put("platform", "android")
                else -> throw IllegalArgumentException("unknown command $cmd")
            }
            ok(data)
        } catch (e: Exception) {
            err(e.message ?: e.toString())
        }
    }

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
