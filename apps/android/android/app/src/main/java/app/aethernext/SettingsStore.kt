package app.aethernext

import android.content.Context
import org.json.JSONObject

/**
 * Every field here must be reachable from the React settings surface and read by
 * native code. Three desktop carry-overs (`startMinimized`, `enginePath`,
 * `endpointPreset`) were persisted, and `endpointPreset` even validated with a
 * user-visible rejection, while no Android code path consumed them — `resolveEngine`
 * deliberately ignored a custom path. Unknown keys in a stored payload are dropped
 * on the next save.
 */
data class Settings(
    var protocol: String = "masque",
    var transport: String = "h2",
    var scanMode: String = "balanced",
    var ipVersion: String = "v4",
    var noize: String = "off",
    var noizeJc: Int = 5,
    var noizeJmin: Int = 50,
    var noizeJmax: Int = 128,
    var noizeIntervalMs: Int = 0,
    var routingMode: String = "tun",
    var socksPort: Int = 1819,
    var httpPort: Int = 1820,
    var launchAtLogin: Boolean = false,
    var peer: String = "",
    var quicInitialFrag: Boolean = false,
    var quicInitialFragSize: Int = 96,
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
        put("launchAtLogin", launchAtLogin)
        put("peer", peer)
        put("quicInitialFrag", quicInitialFrag)
        put("quicInitialFragSize", quicInitialFragSize)
    }

    companion object {
        fun fromJson(o: JSONObject): Settings = Settings(
            protocol = o.optString("protocol", "masque"),
            transport = o.optString("transport", "h2"),
            scanMode = o.optString("scanMode", "balanced"),
            ipVersion = o.optString("ipVersion", "v4"),
            noize = o.optString("noize", "off"),
            noizeJc = o.optInt("noizeJc", 5),
            noizeJmin = o.optInt("noizeJmin", 50),
            noizeJmax = o.optInt("noizeJmax", 128),
            noizeIntervalMs = o.optInt("noizeIntervalMs", 0),
            routingMode = o.optString("routingMode", "tun"),
            socksPort = o.optInt("socksPort", 1819),
            httpPort = o.optInt("httpPort", 1820),
            launchAtLogin = o.optBoolean("launchAtLogin", false),
            peer = o.optString("peer", ""),
            quicInitialFrag = o.optBoolean("quicInitialFrag", false),
            quicInitialFragSize = o.optInt("quicInitialFragSize", 96),
        )
    }
}

/**
 * What the shell believes about the running session.
 *
 * Every field is a `val` on purpose (T215): a published instance is a *snapshot*,
 * handed straight to `getState()` and serialised on another thread. While these
 * were `var`s the session controller mutated them field by field, so the UI could
 * read `status="connected"` together with the previous session's `pid`, or half a
 * transition. Updates go through `SessionController.setRuntime`, which builds a
 * new value and publishes it in one volatile store.
 */
data class RuntimeState(
    val status: String = "disconnected",
    val detail: String = "Ready",
    val pid: Int? = null,
    val endpoint: String? = null,
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
        // One-shot: 1.0.2 migration flag. Preserve existing user preference if already set.
        if (!prefs.getBoolean(KEY_DEFAULTS_V102, false)) {
            val hadSaved = prefs.contains("json")
            val s = readRaw()
            if (!hadSaved && (s.routingMode == "proxy-only" || s.routingMode == "system-proxy")) {
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

        fun load(context: Context): Settings = SettingsStore(context).load()
    }
}
