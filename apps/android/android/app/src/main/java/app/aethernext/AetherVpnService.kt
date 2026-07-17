package app.aethernext

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.app.NotificationCompat
import java.io.FileInputStream
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Full-device routing via Android VpnService.
 *
 * The userspace aether engine still owns encryption (MASQUE/WG). This service
 * establishes a TUN fd and routes app traffic; a companion pump thread can
 * bridge packets when the engine is built with Android TUN support.
 *
 * For the current engine (SOCKS/HTTP first), establishing VPN with a local
 * protect + route still requires engine-side TUN. Until then we:
 *  - create a VpnService session so "Full VPN" permission/profile works
 *  - set disallowed routes carefully
 *  - log that proxy mode remains available on 127.0.0.1
 *
 * When AETHER_TUN=1 and the binary supports Linux TUN, packagers can extend
 * this class to pass the fd via local socket (future hook).
 */
class AetherVpnService : VpnService() {
    private var tun: ParcelFileDescriptor? = null
    private val alive = AtomicBoolean(false)

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        startForegroundNotification()
        if (tun == null) {
            try {
                establishTun()
            } catch (e: Exception) {
                Log.e(TAG, "VPN establish failed: ${e.message}")
                stopSelf()
            }
        }
        return START_STICKY
    }

    private fun establishTun() {
        val builder = Builder()
            .setSession("Aether")
            .setMtu(1280)
            .addAddress("10.0.0.2", 32)
            .addDnsServer("1.1.1.1")
            .addDnsServer("1.0.0.1")
            .addRoute("0.0.0.0", 0)

        // Don't capture ourselves in a loop if using local proxy path.
        try {
            builder.addDisallowedApplication(packageName)
        } catch (_: Exception) {
        }

        tun = builder.establish()
        if (tun == null) {
            throw IllegalStateException("VpnService.Builder.establish() returned null")
        }
        alive.set(true)
        Log.i(TAG, "VPN interface up (full tunnel). Engine handles crypto via AETHER_TUN when supported.")

        // Drain/drop loop keeps the interface from filling; replace with engine bridge later.
        Thread({
            val fd = tun ?: return@Thread
            val input = FileInputStream(fd.fileDescriptor)
            val buf = ByteArray(32767)
            try {
                while (alive.get()) {
                    val n = input.read(buf)
                    if (n <= 0) break
                    // Packets would be forwarded to aether TUN writer when wired.
                }
            } catch (e: Exception) {
                Log.d(TAG, "tun read ended: ${e.message}")
            }
        }, "aether-vpn-drain").start()
    }

    private fun startForegroundNotification() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val ch = NotificationChannel(
                CHANNEL,
                getString(R.string.channel_vpn),
                NotificationManager.IMPORTANCE_LOW,
            )
            getSystemService(NotificationManager::class.java).createNotificationChannel(ch)
        }
        val open = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val n: Notification = NotificationCompat.Builder(this, CHANNEL)
            .setContentTitle(getString(R.string.app_name))
            .setContentText(getString(R.string.notif_vpn))
            .setSmallIcon(R.drawable.ic_launcher)
            .setContentIntent(open)
            .setOngoing(true)
            .build()
        startForeground(NOTIF_ID, n)
    }

    override fun onDestroy() {
        alive.set(false)
        try {
            tun?.close()
        } catch (_: Exception) {
        }
        tun = null
        super.onDestroy()
    }

    companion object {
        private const val TAG = "AetherVpn"
        private const val CHANNEL = "aether_vpn"
        private const val NOTIF_ID = 43
    }
}
