package app.aethernext

import android.content.Context

/**
 * Whether a tunnel was up when this process last died.
 *
 * A kill from outside the app - the LowMemoryKiller, a force-stop from Settings,
 * a native crash in the engine's pipe handler - takes the `VpnService`, the
 * engine child and the notification with it, and nothing in the app learns
 * anything: the next launch reads `disconnected` and shows STANDBY as though the
 * user had never connected, which for a circumvention tool is the difference
 * between "protected" and "unprotected, silently".
 *
 * The record is written when a session reaches `connected` and cleared by a
 * teardown that ran to completion, so what survives into the next process is
 * exactly "ended without having been stopped". It is a fact for the user to see,
 * not an instruction to reconnect on its own: re-establishing a VPN unattended is
 * a different decision, and one that has to be made and tested on a device.
 */
class SessionLedger(context: Context) {
    private val prefs = context.getSharedPreferences(STORE, Context.MODE_PRIVATE)

    /** A tunnel is up in this process. */
    fun markActive(at: Long = System.currentTimeMillis()) {
        prefs.edit().putLong(KEY_ACTIVE_AT, at).apply()
    }

    /** The tunnel came down deliberately, however untidily: nothing to report. */
    fun clearActive() {
        prefs.edit().remove(KEY_ACTIVE_AT).apply()
    }

    /**
     * Consume the record left by an earlier process, if any.
     *
     * Read-and-clear in one step, because the notice must be delivered once: a
     * second `attachUi` on resume, or the next launch after the user has already
     * been told, must not repeat it.
     */
    fun takeUnfinished(): Long? {
        val at = if (prefs.contains(KEY_ACTIVE_AT)) prefs.getLong(KEY_ACTIVE_AT, -1L) else -1L
        if (at < 0) return null
        prefs.edit().remove(KEY_ACTIVE_AT).apply()
        return at
    }

    companion object {
        private const val STORE = "aether_session_ledger"
        private const val KEY_ACTIVE_AT = "activeAt"

        /** The sentence the console shows. Kept here so the test can assert it. */
        fun messageFor(sinceMillis: Long, nowMillis: Long): String {
            val ageSec = ((nowMillis - sinceMillis) / 1000L).coerceAtLeast(0L)
            val age = if (ageSec < 90L) "${ageSec}s" else "${ageSec / 60L}m"
            return "Tunnel ended unexpectedly about $age ago - the system stopped the app while it " +
                "was protecting this device. Traffic is no longer routed. Reconnect to resume."
        }
    }
}
