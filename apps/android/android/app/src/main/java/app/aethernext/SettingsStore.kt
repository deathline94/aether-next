package app.aethernext

import android.content.Context
import org.json.JSONException
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
    /**
     * The state payload the WebView reads — `get_state` and every `session://state`
     * event.
     *
     * `settingsError` is the load-error surface item 10 asks for: `null` when the
     * stored settings are the user's own, otherwise the object from
     * [corruptionPayload]. It rides here rather than on the settings payload because
     * `Settings.toJson()` is the *persisted* key set (pinned by
     * `testPersistedKeysAreExactlyTheOnesNativeCodeReads`) and a load diagnosis is not
     * a setting. The write side of the same story is a `validation` rejection with
     * `field: "settings"` from `save_settings`, which is what `SettingsStore.save`
     * throws while a corrupt blob is unresolved.
     */
    fun toJson(): JSONObject = JSONObject().apply {
        put("status", status)
        put("detail", detail)
        if (pid != null) put("pid", pid) else put("pid", JSONObject.NULL)
        if (endpoint != null) put("endpoint", endpoint) else put("endpoint", JSONObject.NULL)
        put("settingsError", SettingsHealth.snapshot() ?: JSONObject.NULL)
    }
}

class SettingsStore(context: Context) {
    private val prefs = context.getSharedPreferences("aether_settings", Context.MODE_PRIVATE)

    /** What the last [load] of *this* store found. Defaults are not a verdict. */
    private var state: SettingsReadState = SettingsReadState.Missing

    /**
     * Read the user's settings.
     *
     * Three outcomes, and the third used to be the first one's answer: a blob that
     * exists but cannot be honoured now stays on disk untouched, is kept as the reason
     * [save] refuses, and is reported to the UI rather than replaced.
     */
    fun load(): Settings {
        val raw = prefs.getString(KEY_BLOB, null)
        val oneShotPending = !prefs.getBoolean(KEY_DEFAULTS_V102, false)

        if (raw == null) {
            // MISSING: there is no user value to destroy, so publishing defaults is safe.
            state = SettingsReadState.Missing
            SettingsHealth.clear()
            if (oneShotPending) {
                val fresh = Settings()
                prefs.edit()
                    .putString(KEY_BLOB, fresh.toJson().toString())
                    .putBoolean(KEY_DEFAULTS_V102, true)
                    .apply()
                return fresh
            }
            return Settings()
        }

        val read = parseStored(raw)
        if (read is StoredRead.Corrupt) {
            state = SettingsReadState.Corrupt
            quarantine(raw, read)
            SettingsHealth.publish(reason = read.reason, field = read.field, atMs = currentTimeMillis())
            return Settings()
        }

        val settings = (read as StoredRead.Ok).settings
        state = SettingsReadState.Healthy
        // A successful read *is* the recovery: the quarantined blob parses and its
        // values hold, so the write lock that corruption imposed comes off.
        recoverQuarantine()
        SettingsHealth.clear()
        if (oneShotPending) {
            // 1.0.2 one-shot: normalise a stored payload once, after it parsed. The
            // same rewrite that used to run on a corrupt blob, gated on the read that
            // makes it safe.
            prefs.edit()
                .putString(KEY_BLOB, settings.toJson().toString())
                .putBoolean(KEY_DEFAULTS_V102, true)
                .apply()
        }
        return settings
    }

    /**
     * Persist settings.
     *
     * Refused while a corrupt blob is unresolved: the whole damage this guard prevents
     * is a save — any save, including the one `connect()` makes before it starts —
     * writing over the bytes a user spent weeks getting right, on the strength of a
     * parse error this side could not read. [resetCorruptSettings] is the explicit way
     * through, and the quarantined copy survives it.
     */
    fun save(settings: Settings) {
        if (hasUnresolvedCorruption()) {
            throw SettingRejected(
                "settings",
                "Settings were not saved: the stored settings are corrupt and would be " +
                    "overwritten. Choose Reset settings to accept defaults, or restore the " +
                    "saved file, then save again.",
            )
        }
        SessionController.validateSettings(settings)
        prefs.edit().putString(KEY_BLOB, settings.toJson().toString()).apply()
    }

    /** Whether a corrupt blob is still on disk, unacknowledged. */
    fun hasUnresolvedCorruption(): Boolean =
        prefs.contains(KEY_CORRUPT_RAW) && !prefs.getBoolean(KEY_CORRUPT_ACK, false)

    fun readState(): SettingsReadState = state

    /** Whether this store's last read produced settings the user actually wrote. */
    fun settingsAreHealthy(): Boolean = state == SettingsReadState.Healthy

    /**
     * Accept that the stored blob is gone: keep the rejected bytes quarantined, clear
     * the write refusal, and put defaults on disk.
     *
     * The user's side of the deal is that nothing is discarded silently — this is the
     * only path that replaces a corrupt value, and it leaves the original readable for
     * as long as a later corruption does not need the slot.
     */
    fun resetCorruptSettings(): Settings {
        prefs.edit().putBoolean(KEY_CORRUPT_ACK, true).apply()
        SettingsHealth.clear()
        val defaults = Settings()
        prefs.edit().putString(KEY_BLOB, defaults.toJson().toString()).apply()
        state = SettingsReadState.Healthy
        return defaults
    }

    /** The quarantined bytes, when a read was refused. Never rewritten, never truncated. */
    fun quarantinedBlob(): String? = try {
        prefs.getString(KEY_CORRUPT_RAW, null)
    } catch (_: Exception) {
        null
    }

    private fun quarantine(raw: String, read: StoredRead.Corrupt) {
        try {
            // A fresh corruption is pending again even if the last one was
            // acknowledged, and the quarantine slot holds the bytes that are unreadable
            // *now*: a copy the user already chose to discard with
            // [resetCorruptSettings] is not evidence anyone can still act on.
            prefs.edit()
                .putString(KEY_CORRUPT_RAW, raw)
                .putString(KEY_CORRUPT_REASON, read.reason)
                .putLong(KEY_CORRUPT_AT, currentTimeMillis())
                .remove(KEY_CORRUPT_ACK)
                .apply()
        } catch (e: Exception) {
            android.util.Log.e("SettingsStore", "could not quarantine the corrupt blob: ${e.message}")
        }
    }

    private fun recoverQuarantine() {
        if (!prefs.contains(KEY_CORRUPT_RAW)) {
            if (prefs.contains(KEY_CORRUPT_ACK)) prefs.edit().remove(KEY_CORRUPT_ACK).apply()
            return
        }
        // A reset left the rejected bytes behind on purpose, and the acknowledgement is
        // what keeps them from imposing a write lock forever. Keep both.
        if (prefs.getBoolean(KEY_CORRUPT_ACK, false)) return
        // The blob parses now: the quarantine and the authoritative copy are the same
        // bytes, so the pending flag and the copy can both go.
        prefs.edit()
            .remove(KEY_CORRUPT_RAW)
            .remove(KEY_CORRUPT_REASON)
            .remove(KEY_CORRUPT_AT)
            .remove(KEY_CORRUPT_ACK)
            .apply()
    }

    /**
     * Parse and *validate* one stored blob.
     *
     * Validation is the half that was missing. `Settings.fromJson` reads every field
     * with an `opt*` default, so `{"protocol":"openvpn"}` — valid JSON, a value no
     * surface of this app can produce — came back as a settings object with a protocol
     * the engine will not accept, was indistinguishable from one the user had written,
     * and a later save made it permanent. "A field the UI could never have produced" is
     * corruption, and it is reported as such.
     *
     * Representation leniency is kept deliberately: `{"socksPort":"1819"}` still reads,
     * because `optInt` coerces it to the number the user asked for and refusing a blob
     * over a quote would lock a working device out of saving. Pinned by
     * `aNumberStoredAsAStringStillReadsBecauseThatIsWhatJsonCoercionMeans`.
     */
    private fun parseStored(raw: String): StoredRead = try {
        val settings = Settings.fromJson(JSONObject(raw))
        SessionController.validateSettings(settings)
        StoredRead.Ok(settings)
    } catch (e: SettingRejected) {
        StoredRead.Corrupt(e.message ?: "stored settings are not valid", e.field)
    } catch (e: JSONException) {
        StoredRead.Corrupt("the stored settings are not readable: ${e.message ?: e.javaClass.simpleName}", null)
    } catch (e: Exception) {
        // Anything else a blob can provoke — an OOM-shaped `JSONObject` parse, a
        // `ClassCastException` from a field typed as a list — is also "cannot be
        // honoured", and none of it may take the read path down with it.
        StoredRead.Corrupt(e.message ?: e.javaClass.simpleName, null)
    }

    /** Monotonic-ish stamp for the report; overridable so a test can pin it. */
    private fun currentTimeMillis(): Long = System.currentTimeMillis()

    companion object {
        /** The 1.0.2 one-shot. Internal so a test can prove a corrupt read leaves it pending. */
        internal const val KEY_DEFAULTS_V102 = "defaults_v102"

        /** The user's blob. Only ever written by a read that succeeded or a reset. */
        internal const val KEY_BLOB = "json"

        /** The quarantined copy, its reason, and the moment it was set aside. */
        internal const val KEY_CORRUPT_RAW = "corrupt_json"
        internal const val KEY_CORRUPT_REASON = "corrupt_reason"
        internal const val KEY_CORRUPT_AT = "corrupt_at"
        internal const val KEY_CORRUPT_ACK = "corrupt_acknowledged"

        fun load(context: Context): Settings = SettingsStore(context).load()
    }
}

/** How the persisted blob read. `Missing` and `Corrupt` must never share an answer. */
enum class SettingsReadState {
    /** Values the user wrote, read and validated. */
    Healthy,

    /** Nothing stored yet: a fresh install, or a cleared app. */
    Missing,

    /** Something is stored, and it cannot be honoured. Preserved, not replaced. */
    Corrupt,
}

private sealed interface StoredRead {
    data class Ok(val settings: Settings) : StoredRead
    data class Corrupt(val reason: String, val field: String?) : StoredRead
}

/**
 * The process-wide view of "the user's settings are corrupt", published by
 * [SettingsStore.load] and read by [RuntimeState.toJson].
 *
 * A holder rather than a return value because the two are not in the same conversation:
 * the store that notices is built by `SessionController`, `BootReceiver` and
 * `EngineRunner` independently, and the surface that has to say it out loud is the
 * `session://state` stream. The field is a *report*, not an override — it never
 * changes the settings any caller received.
 */
internal object SettingsHealth {
    @Volatile
    private var report: org.json.JSONObject? = null

    fun publish(reason: String, field: String?, atMs: Long) {
        report = corruptionPayload(reason, field, atMs)
    }

    fun clear() {
        report = null
    }

    fun isCorrupt(): Boolean = report != null

    /** The object to embed, or `null` when there is nothing to report. */
    fun snapshot(): org.json.JSONObject? = report

    /** Reset the published report. Tests only, so a suite cannot inherit a corruption. */
    fun reset() {
        report = null
    }
}

/**
 * The frontend contract for a corrupt blob, as one object.
 *
 * `settingsError` on `session://state` / `get_state` is either `null` or:
 * `{ "state": "corrupt", "reason": <sentence>, "field": <setting name|null>,
 *    "detectedAt": <epoch ms>, "action": "reset" }`.
 *
 * `action` is the affordance the UI has to offer: the payload names *which* choice
 * resolves it (an explicit reset), because every other path is refused on purpose.
 * `field` is the setting to point the user at when there is one — `null` means the blob
 * itself could not be read, so no field is to blame.
 */
internal fun corruptionPayload(reason: String, field: String?, atMs: Long): org.json.JSONObject =
    org.json.JSONObject().apply {
        put("state", "corrupt")
        put("reason", reason)
        put("field", field ?: org.json.JSONObject.NULL)
        put("detectedAt", atMs)
        put("action", "reset")
    }
