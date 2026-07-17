package app.aethernext

import android.content.Context
import org.json.JSONObject

data class Settings(
    var protocol: String = "masque",
    var transport: String = "h2",
    var scanMode: String = "balanced",
    var ipVersion: String = "v4",
    var noize: String = "firewall",
    var routingMode: String = "proxy-only",
    var socksPort: Int = 1819,
    var httpPort: Int = 1820,
    var startMinimized: Boolean = false,
    var launchAtLogin: Boolean = false,
    var enginePath: String = "",
) {
    fun toJson(): JSONObject = JSONObject().apply {
        put("protocol", protocol)
        put("transport", transport)
        put("scanMode", scanMode)
        put("ipVersion", ipVersion)
        put("noize", noize)
        put("routingMode", routingMode)
        put("socksPort", socksPort)
        put("httpPort", httpPort)
        put("startMinimized", startMinimized)
        put("launchAtLogin", launchAtLogin)
        put("enginePath", enginePath)
    }

    companion object {
        fun fromJson(o: JSONObject): Settings = Settings(
            protocol = o.optString("protocol", "masque"),
            transport = o.optString("transport", "h2"),
            scanMode = o.optString("scanMode", "balanced"),
            ipVersion = o.optString("ipVersion", "v4"),
            noize = o.optString("noize", "firewall"),
            routingMode = o.optString("routingMode", "proxy-only"),
            socksPort = o.optInt("socksPort", 1819),
            httpPort = o.optInt("httpPort", 1820),
            startMinimized = o.optBoolean("startMinimized", false),
            launchAtLogin = o.optBoolean("launchAtLogin", false),
            enginePath = o.optString("enginePath", ""),
        )
    }
}

data class RuntimeState(
    var status: String = "disconnected",
    var detail: String = "Ready",
    var pid: Int? = null,
    var endpoint: String? = null,
) {
    fun toJson(): JSONObject = JSONObject().apply {
        put("status", status)
        put("detail", detail)
        if (pid != null) put("pid", pid) else put("pid", JSONObject.NULL)
        if (endpoint != null) put("endpoint", endpoint) else put("endpoint", JSONObject.NULL)
    }
}

class SettingsStore(context: Context) {
    private val prefs = context.getSharedPreferences("aether_settings", Context.MODE_PRIVATE)

    fun load(): Settings {
        val raw = prefs.getString("json", null) ?: return Settings()
        return try {
            Settings.fromJson(JSONObject(raw))
        } catch (_: Exception) {
            Settings()
        }
    }

    fun save(settings: Settings) {
        prefs.edit().putString("json", settings.toJson().toString()).apply()
    }
}
