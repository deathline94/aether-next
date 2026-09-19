package app.aethernext

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.Build
import androidx.core.app.NotificationCompat

class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent?) {
        if (intent?.action != Intent.ACTION_BOOT_COMPLETED) return
        val store = SettingsStore(context)
        val s = store.load()
        if (!s.launchAtLogin) return

        val launch = Intent(context, MainActivity::class.java).apply {
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP)
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            // Android 10+ restricts background activity starts (BAL).
            // Post a notification allowing the user to launch with a single tap.
            try {
                val nm = context.getSystemService(Context.NOTIFICATION_SERVICE) as? NotificationManager
                val channelId = "aether_boot_channel"
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O && nm != null) {
                    val channel = NotificationChannel(
                        channelId,
                        "Aether Launch",
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
                val notification = NotificationCompat.Builder(context, channelId)
                    .setContentTitle(context.getString(R.string.app_name))
                    .setContentText("Aether Next is ready. Tap to open.")
                    .setSmallIcon(R.mipmap.ic_launcher)
                    .setContentIntent(pendingIntent)
                    .setAutoCancel(true)
                    .build()
                nm?.notify(1001, notification)
            } catch (_: Exception) {
            }
        } else {
            try {
                context.startActivity(launch)
            } catch (_: Exception) {
            }
        }
    }
}
