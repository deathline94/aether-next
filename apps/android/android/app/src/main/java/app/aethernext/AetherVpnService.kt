package app.aethernext

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.app.NotificationCompat
import androidx.core.app.ServiceCompat
import java.io.File
import java.io.FileOutputStream
import java.util.concurrent.Executors

/**
 * Full-device VPN via Android [VpnService] + hev-socks5-tunnel (tun2socks).
 *
 * App traffic is routed into a TUN interface. hev forwards TCP/UDP through the
 * local aether SOCKS5 proxy (127.0.0.1:socksPort). Our own package is excluded
 * so the engine's outbound CF connections are not looped back into the TUN.
 *
 * DNS uses hev mapdns (fake resolver at 198.18.0.2) so name lookups go through
 * SOCKS rather than raw UDP to public resolvers.
 */
class AetherVpnService : VpnService() {
    private var tun: ParcelFileDescriptor? = null
    private var hevStarted = false
    private var stopRequested = false

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            stopRequested = true
            // Do not call startForeground on STOP — just tear down.
            worker.execute {
                stopTunnel()
                mainHandler.post { stopSelf() }
            }
            return START_NOT_STICKY
        }
        try {
            startForegroundNotification()
        } catch (e: Exception) {
            Log.e(TAG, "startForeground failed: ${e.message}", e)
            SessionController.getOrNull()?.onVpnFailed("VPN foreground start blocked: ${e.message}")
            stopSelf()
            return START_NOT_STICKY
        }
        if (tun == null) {
            val socksPort = intent?.getIntExtra(EXTRA_SOCKS_PORT, -1) ?: -1
            worker.execute {
                try {
                    check(socksPort in 1024..65535) { "VPN start missing valid SOCKS port" }
                    check(nativeLoaded) { "hev-socks5-tunnel native library unavailable" }
                    establishTun(socksPort)
                    mainHandler.post {
                        SessionController.getOrNull()?.onVpnEstablished()
                    }
                } catch (e: Exception) {
                    Log.e(TAG, "VPN establish failed: ${e.message}", e)
                    stopTunnel()
                    mainHandler.post {
                        SessionController.getOrNull()?.onVpnFailed(e.message ?: "VPN establish failed")
                        stopSelf()
                    }
                } catch (e: UnsatisfiedLinkError) {
                    Log.e(TAG, "VPN native call failed: ${e.message}", e)
                    stopTunnel()
                    mainHandler.post {
                        SessionController.getOrNull()?.onVpnFailed("VPN native library incompatible")
                        stopSelf()
                    }
                }
            }
        }
        return START_NOT_STICKY
    }

    private fun establishTun(socksPort: Int) {
        val builder = Builder()
            .setSession("Aether Next")
            .setMtu(MTU)
            .setBlocking(false)
            // Same address scheme as SocksTun / hev defaults.
            .addAddress(TUN_ADDR, 32)
            .addDnsServer(MAPPED_DNS)
            .addRoute("0.0.0.0", 0)
            // IPv6 tunnel not implemented: blackhole IPv6 so traffic cannot bypass full VPN.
            // Apps needing real IPv6 fail closed (no silent leak).
            .addAddress(TUN_ADDR_V6, 128)
            .addRoute("::", 0)

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
        val conf = File(noBackupFilesDir, "hev-socks5-tunnel.yml")
        // udp:udp — aether implements standard SOCKS5 UDP ASSOCIATE (not UDP-in-TCP).
        // mapdns — resolve names via SOCKS so apps do not depend on raw UDP DNS.
        // icmp drop — avoid NTP/oracle side-channels from reply mode.
        val yaml = """
            |tunnel:
            |  mtu: $MTU
            |  ipv4: $TUN_ADDR
            |  icmp: 'drop'
            |socks5:
            |  port: $socksPort
            |  address: 127.0.0.1
            |  udp: 'udp'
            |mapdns:
            |  address: $MAPPED_DNS
            |  port: 53
            |  network: 240.0.0.0
            |  netmask: 240.0.0.0
            |  cache-size: 10000
            |misc:
            |  task-stack-size: 81920
            |  connect-timeout: 10000
            |  log-level: warn
            |""".trimMargin()
        FileOutputStream(conf, false).use { it.write(yaml.toByteArray(Charsets.UTF_8)) }
        try {
            conf.setReadable(true, true)
            conf.setWritable(true, true)
        } catch (_: Exception) {
        }
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

    private fun stopTunnel() {
        if (hevStarted) {
            try {
                TProxyStopService()
            } catch (e: Exception) {
                Log.w(TAG, "hev stop: ${e.message}")
            } catch (e: UnsatisfiedLinkError) {
                Log.w(TAG, "hev stop native: ${e.message}")
            }
            hevStarted = false
            // Give hev threads a beat to release the TUN fd before close (avoids SIGSEGV).
            try {
                Thread.sleep(150)
            } catch (_: InterruptedException) {
            }
        }
        try {
            tun?.close()
        } catch (_: Exception) {
        }
        tun = null
    }

    override fun onRevoke() {
        stopRequested = true
        stopTunnel()
        SessionController.getOrNull()?.onVpnFailed("VPN permission revoked")
        stopSelf()
        super.onRevoke()
    }

    override fun onDestroy() {
        val unexpected = !stopRequested && hevStarted
        stopTunnel()
        if (unexpected) {
            SessionController.getOrNull()?.onVpnFailed("VPN service stopped by system")
        }
        super.onDestroy()
    }

    companion object {
        private const val TAG = "AetherVpn"
        private const val CHANNEL = "aether_vpn"
        private const val NOTIF_ID = 43
        private const val MTU = 1280
        private const val TUN_ADDR = "198.18.0.1"
        // Unique local address for blackhole IPv6 route (no real IPv6 tunnel yet).
        private const val TUN_ADDR_V6 = "fd00:aether::1"
        private const val MAPPED_DNS = "198.18.0.2"
        @Volatile
        private var nativeLoaded = false
        private val worker = Executors.newSingleThreadExecutor { r ->
            Thread(r, "aether-vpn-worker").apply { isDaemon = true }
        }
        private val mainHandler = Handler(Looper.getMainLooper())
        const val EXTRA_SOCKS_PORT = "socks_port"
        const val ACTION_STOP = "app.aethernext.VPN_STOP"

        init {
            try {
                System.loadLibrary("hev-socks5-tunnel")
                nativeLoaded = true
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
