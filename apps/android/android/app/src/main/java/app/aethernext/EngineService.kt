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
        // Do not tear down an active tunnel when Recents swipes the UI away: the
        // foreground notification and Quick Settings tile own tunnel control. Only
        // if no session was actually started do we stop the keeper service cleanly.
        val ctrl = SessionController.getOrNull() ?: return
        if (ctrl.getState().status == "disconnected") {
            stopSelf()
        }
    }

    override fun onCreate() {
        super.onCreate()
        createChannel()
        ensureForeground()
    }

    private fun ensureForeground() {
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
        try {
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
        } catch (e: Exception) {
            android.util.Log.e("AetherEngineSvc", "startForeground failed: ${e.message}", e)
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        ensureForeground()
        val action = ServiceRestartPolicy.decide(
            role = ServiceRole.EngineKeeper,
            redelivered = intent == null || (flags and START_FLAG_REDELIVERY) != 0,
            userAskedToStop = false,
        )
        if (intent == null) {
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
