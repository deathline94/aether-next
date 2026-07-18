package app.aethernext

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.app.NotificationCompat
import java.io.File
import java.io.FileOutputStream

/**
 * Full-device VPN via Android [VpnService] + hev-socks5-tunnel (tun2socks).
 *
 * App traffic is routed into a TUN interface. hev forwards TCP/UDP through the
 * local aether SOCKS5 proxy (127.0.0.1:socksPort). Our own package is excluded
 * so the engine's outbound CF connections are not looped back into the TUN.
 */
class AetherVpnService : VpnService() {
    private var tun: ParcelFileDescriptor? = null
    private var hevStarted = false

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            stopTunnel()
            stopSelf()
            return START_NOT_STICKY
        }
        startForegroundNotification()
        if (tun == null) {
            val socksPort = intent?.getIntExtra(EXTRA_SOCKS_PORT, 1819) ?: 1819
            try {
                establishTun(socksPort)
            } catch (e: Exception) {
                Log.e(TAG, "VPN establish failed: ${e.message}", e)
                stopTunnel()
                stopSelf()
            }
        }
        return START_STICKY
    }

    private fun establishTun(socksPort: Int) {
        val builder = Builder()
            .setSession("Aether Next")
            .setMtu(MTU)
            .setBlocking(false)
            .addAddress("10.0.0.2", 32)
            .addDnsServer("1.1.1.1")
            .addDnsServer("1.0.0.1")
            .addRoute("0.0.0.0", 0)

        // Keep engine + hev sockets off the TUN (otherwise infinite loop).
        try {
            builder.addDisallowedApplication(packageName)
        } catch (_: Exception) {
        }

        val established = builder.establish()
        if (established == null) {
            throw IllegalStateException("VpnService.Builder.establish() returned null")
        }
        tun = established

        val configPath = writeHevConfig(socksPort)
        Log.i(TAG, "starting hev tun2socks fd=${established.fd} socks=127.0.0.1:$socksPort conf=$configPath")
        TProxyStartService(configPath, established.fd)
        hevStarted = true
        Log.i(TAG, "VPN + hev-socks5-tunnel active")
    }

    private fun writeHevConfig(socksPort: Int): String {
        val conf = File(cacheDir, "hev-socks5-tunnel.yml")
        // udp:tcp — relay UDP over SOCKS TCP (works with aether SOCKS without UDP ASSOCIATE).
        val yaml = """
            |tunnel:
            |  mtu: $MTU
            |  ipv4: 10.0.0.2
            |  icmp: 'reply'
            |socks5:
            |  port: $socksPort
            |  address: 127.0.0.1
            |  udp: 'tcp'
            |misc:
            |  task-stack-size: 86016
            |  connect-timeout: 10000
            |  log-level: warn
            |""".trimMargin()
        FileOutputStream(conf, false).use { it.write(yaml.toByteArray(Charsets.UTF_8)) }
        return conf.absolutePath
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
            .setSmallIcon(R.mipmap.ic_launcher)
            .setContentIntent(open)
            .setOngoing(true)
            .build()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(NOTIF_ID, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else {
            startForeground(NOTIF_ID, n)
        }
    }

    private fun stopTunnel() {
        if (hevStarted) {
            try {
                TProxyStopService()
            } catch (e: Exception) {
                Log.w(TAG, "hev stop: ${e.message}")
            }
            hevStarted = false
        }
        try {
            tun?.close()
        } catch (_: Exception) {
        }
        tun = null
    }

    override fun onRevoke() {
        stopTunnel()
        stopSelf()
        super.onRevoke()
    }

    override fun onDestroy() {
        stopTunnel()
        super.onDestroy()
    }

    companion object {
        private const val TAG = "AetherVpn"
        private const val CHANNEL = "aether_vpn"
        private const val NOTIF_ID = 43
        private const val MTU = 1280
        const val EXTRA_SOCKS_PORT = "socks_port"
        const val ACTION_STOP = "app.aethernext.VPN_STOP"

        init {
            try {
                System.loadLibrary("hev-socks5-tunnel")
            } catch (e: UnsatisfiedLinkError) {
                Log.e(TAG, "failed to load libhev-socks5-tunnel: ${e.message}")
            }
        }

        /** hev JNI (registered in hev-jni.c for AetherVpnService). */
        @JvmStatic
        private external fun TProxyStartService(configPath: String, fd: Int)

        @JvmStatic
        private external fun TProxyStopService()

        @JvmStatic
        private external fun TProxyGetStats(): LongArray
    }
}
