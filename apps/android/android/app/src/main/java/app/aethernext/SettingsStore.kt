package app.aethernext

import android.content.Context
import org.json.JSONObject

data class Settings(
    var protocol: String = "masque",
    var transport: String = "h2",
    var scanMode: String = "balanced",
    var ipVersion: String = "v4",
    var noize: String = "off",
    var noizeJc: Int = 4,
    var noizeJmin: Int = 48,
    var noizeJmax: Int = 190,
    var noizeIntervalMs: Int = 4,
    var routingMode: String = "tun",
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
        put("noizeJc", noizeJc)
        put("noizeJmin", noizeJmin)
        put("noizeJmax", noizeJmax)
        put("noizeIntervalMs", noizeIntervalMs)
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
            noize = o.optString("noize", "off"),
            noizeJc = o.optInt("noizeJc", 4),
            noizeJmin = o.optInt("noizeJmin", 48),
            noizeJmax = o.optInt("noizeJmax", 190),
            noizeIntervalMs = o.optInt("noizeIntervalMs", 4),
            routingMode = o.optString("routingMode", "tun"),
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
        // One-shot: 1.0.2 switches default routing to full VPN (tun).
        if (!prefs.getBoolean(KEY_DEFAULTS_V102, false)) {
            val s = readRaw()
            if (s.routingMode == "proxy-only" || s.routingMode == "system-proxy") {
                s.routingMode = "tun"
            }
            prefs.edit()
                .putString("json", s.toJson().toString())
                .putBoolean(KEY_DEFAULTS_V102, true)
                .apply()
            return s
        }
        return readRaw()
    }

    fun save(settings: Settings) {
        prefs.edit().putString("json", settings.toJson().toString()).apply()
    }

    private fun readRaw(): Settings {
        val raw = prefs.getString("json", null) ?: return Settings()
        return try {
            Settings.fromJson(JSONObject(raw))
        } catch (_: Exception) {
            Settings()
        }
    }

    companion object {
        private const val KEY_DEFAULTS_V102 = "defaults_v102"
    }
}
