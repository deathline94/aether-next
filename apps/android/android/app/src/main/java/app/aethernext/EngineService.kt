package app.aethernext

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import androidx.core.app.ServiceCompat

/** Keeps the process alive while the tunnel engine is running. */
class EngineService : Service() {
    override fun onBind(intent: Intent?): IBinder? = null

    /**
     * The task was swiped away from Recents.
     *
     * Android does not promise `onDestroy` on the activity in this path, and it
     * definitely does not promise it when an OEM kills the UI while keeping a
     * foreground service's process alive — which leaves a full-device tunnel and
     * an engine running with nothing on screen that could ever stop them. The
     * controller owns that decision: [SessionController.shutdownHeadless] no-ops
     * while any UI is still attached (the task may have been removed with the
     * activity living in another one) and tears the session down when none is.
     */
    override fun onTaskRemoved(rootIntent: Intent?) {
        super.onTaskRemoved(rootIntent)
        SessionController.getOrNull()?.shutdownHeadless("the app's task was swiped away")
    }

    override fun onCreate() {
        super.onCreate()
        createChannel()
        val open = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val n: Notification = NotificationCompat.Builder(this, CHANNEL)
            .setContentTitle(getString(R.string.app_name))
            .setContentText(getString(R.string.notif_running))
            .setSmallIcon(R.drawable.ic_notification)
            .setContentIntent(open)
            .setOngoing(true)
            .build()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            ServiceCompat.startForeground(
                this,
                NOTIF_ID,
                n,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE,
            )
        } else {
            startForeground(NOTIF_ID, n)
        }
    }

    /**
     * Deliberately not `START_STICKY` — and the reason is now a rule, not a comment.
     *
     * This service exists only to keep the process of a live session alive; the tunnel
     * itself is [AetherVpnService] and the engine is its child process, and both die
     * with this process. Being restarted after such a kill would re-run `onCreate`,
     * re-post the "Aether is protecting you" notification and have nothing behind it —
     * a lie in the status bar, which is worse than the honest absence the user can
     * see. What the death leaves behind is a [SessionLedger] record instead, which the
     * next launch reports as an unexpected stop rather than hiding it, and
     * `launchAtLogin` — the explicit resume switch — is what lets the user start again
     * with one tap.
     *
     * The null-intent branch is that decision applied rather than asserted: the policy
     * is asked, and answers [StartAction.RemainStopped] for the keeper role whatever
     * the system handed back, because a redelivered keeper has no session to keep.
     */
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val action = ServiceRestartPolicy.decide(
            role = ServiceRole.EngineKeeper,
            redelivered = intent == null || (flags and START_FLAG_REDELIVERY) != 0,
            userAskedToStop = false,
        )
        if (intent == null) {
            // The start came back with no intent: the session it was keeping is gone,
            // so the keeper has to go with it rather than sit in the foreground.
            stopSelfResult(startId)
        }
        return ServiceRestartPolicy.startCommandFor(action)
    }

    private fun createChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val ch = NotificationChannel(
                CHANNEL,
                getString(R.string.channel_engine),
                NotificationManager.IMPORTANCE_LOW,
            )
            getSystemService(NotificationManager::class.java).createNotificationChannel(ch)
        }
    }

    companion object {
        private const val CHANNEL = "aether_engine"
        private const val NOTIF_ID = 42
    }
}
