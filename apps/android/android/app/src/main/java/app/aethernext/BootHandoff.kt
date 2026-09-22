package app.aethernext

import android.content.Context
import android.util.Log

/**
 * The boot handoff's state, kept out of [BootReceiver] so the "Launch at login"
 * promise can be checked rather than assumed (T218).
 *
 * The receiver used to call `notify()` inside `try { … } catch (_: Exception) { }`
 * and nothing else. When `POST_NOTIFICATIONS` is denied — the default for a fresh
 * install that has not answered the runtime prompt yet, which is exactly the state
 * a device is in right after a boot — `notify()` is silently dropped, and every
 * other failure was swallowed too. "Launch at login" was a no-op that reported
 * success. There is no way for a broadcast receiver to know the notification was
 * dropped, so it asks the notification manager up front and, when nothing can be
 * shown, records why for the app to say out loud the next time it is open.
 */
internal object BootHandoff {
    private const val TAG = "BootHandoff"
    private const val PREFS = "aether_boot"
    private const val KEY_PENDING = "pending_start"

    /** What the user has to do, phrased for the in-app log stream. */
    const val BLOCKED_MESSAGE =
        "Launch at login could not show its 'tap to start' notification because notifications are " +
            "blocked for Aether Next. Aether did not start. Enable notifications in " +
            "System Settings > Apps > Aether Next > Notifications, then tap Connect."

    const val FAILED_MESSAGE_PREFIX =
        "Launch at login could not post its notification: "

    /**
     * The decision the receiver makes, as a function so it can be asserted:
     * `null` when the tap-to-start notification can be shown, otherwise the
     * message to replay in the app.
     */
    fun planFor(canNotify: Boolean): String? = if (canNotify) null else BLOCKED_MESSAGE

    /**
     * Record that the boot handoff needs the user. `null` means the notification
     * went out and there is nothing to replay.
     */
    fun markStartPending(context: Context, reason: String) {
        try {
            context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
                .putString(KEY_PENDING, reason)
                .apply()
        } catch (e: Exception) {
            Log.e(TAG, "could not record the pending boot handoff: ${e.message}")
        }
    }

    /** Read *and* clear, so a replayed notice appears once per boot. */
    fun consumePendingStart(context: Context): String? {
        val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        val pending = try {
            prefs.getString(KEY_PENDING, null)
        } catch (e: Exception) {
            Log.w(TAG, "could not read the pending boot handoff: ${e.message}")
            null
        }
        if (pending != null) prefs.edit().remove(KEY_PENDING).apply()
        return pending
    }

    /**
     * Whether a notification can actually be seen right now.
     *
     * `NotificationManager.areNotificationsEnabled()` covers the per-app master
     * switch (and, on 13+, the denied `POST_NOTIFICATIONS` runtime permission,
     * because the channel group is then suppressed). A missing manager counts as
     * blocked: the honest default is to say so, not to pretend.
     */
    fun canNotify(context: Context): Boolean {
        val nm = try {
            context.getSystemService(Context.NOTIFICATION_SERVICE) as? android.app.NotificationManager
        } catch (e: Exception) {
            Log.w(TAG, "notification manager unavailable: ${e.message}")
            null
        }
        return try {
            nm?.areNotificationsEnabled() ?: false
        } catch (e: Exception) {
            Log.w(TAG, "areNotificationsEnabled failed: ${e.message}")
            false
        }
    }
}
