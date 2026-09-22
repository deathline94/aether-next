package app.aethernext

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.Build
import android.util.Log
import androidx.core.app.NotificationCompat

/**
 * "Launch at login".
 *
 * A boot receiver cannot start a VPN, cannot start an activity in the background on
 * API 10+, and — since 13 — cannot even show a notification unless the runtime
 * permission was granted, which a device that just rebooted after a fresh install
 * typically has not answered. The old code posted a notification inside
 * `catch (_: Exception) { }` and, on pre-Q, called `startActivity` from the
 * receiver. Both branches reported success and neither could be observed to fail,
 * so the setting was a silent no-op (T218).
 *
 * It now asks whether a notification can be shown at all. If it cannot, the reason
 * is recorded for the app to display on its next open ([BootHandoff.consumePendingStart]);
 * the app does not claim it started something it did not. The pre-Q `startActivity`
 * branch is gone: minSdk is 26 and every device this ships on is API 29+, where
 * that call is rejected by the background-activity-start policy.
 */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent?) {
        if (intent?.action != Intent.ACTION_BOOT_COMPLETED) return
        handleBoot(context)
    }

    /**
     * The part that does not need a broadcast: split out so a test can drive it —
     * `Intent` is a stub under a JVM unit test, so the action check above is the
     * only thing that cannot be exercised there.
     */
    internal fun handleBoot(context: Context) {
        val s = SettingsStore(context).load()
        if (!s.launchAtLogin) return

        val launch = Intent(context, MainActivity::class.java).apply {
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP)
        }

        if (!BootHandoff.canNotify(context)) {
            val reason = BootHandoff.planFor(canNotify = false) ?: BootHandoff.BLOCKED_MESSAGE
            Log.e(TAG, "boot start skipped: notifications are blocked for this app")
            BootHandoff.markStartPending(context, reason)
            return
        }

        val posted = try {
            postTapToStart(context, launch)
        } catch (e: Exception) {
            Log.e(TAG, "boot notification failed: ${e.message}", e)
            false
        }

        if (!posted) {
            // Something still stands between the user and a way in — say so on the
            // next launch instead of leaving the setting to appear broken at random.
            val detail = BootHandoff.FAILED_MESSAGE_PREFIX +
                "the notification could not be posted. Tap Connect to start Aether Next."
            Log.e(TAG, "boot start skipped: notification could not be posted")
            BootHandoff.markStartPending(context, detail)
        }
    }

    /** @return false when the manager refused the notification outright. */
    private fun postTapToStart(context: Context, launch: Intent): Boolean {
        val nm = context.getSystemService(Context.NOTIFICATION_SERVICE) as? NotificationManager
            ?: return false
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL,
                context.getString(R.string.channel_boot),
                NotificationManager.IMPORTANCE_DEFAULT,
            )
            nm.createNotificationChannel(channel)
        }
        val pendingIntent = PendingIntent.getActivity(
            context,
            0,
            launch,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val notification = NotificationCompat.Builder(context, CHANNEL)
            .setContentTitle(context.getString(R.string.app_name))
            .setContentText(context.getString(R.string.notif_tap_to_start))
            .setSmallIcon(R.drawable.ic_notification)
            .setContentIntent(pendingIntent)
            .setAutoCancel(true)
            .build()
        return try {
            nm.notify(NOTIF_ID, notification)
            true
        } catch (e: Exception) {
            Log.e(TAG, "notify failed: ${e.message}", e)
            false
        }
    }

    companion object {
        private const val TAG = "BootReceiver"
        private const val CHANNEL = "aether_boot_channel"
        private const val NOTIF_ID = 1001
    }
}
