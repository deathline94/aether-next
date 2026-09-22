package app.aethernext

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
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
 *
 * Loop avoidance (`addDisallowedApplication`) is fail-closed and cannot be
 * replaced by `protect()` — see [LoopAvoidance] for the reasoning (T208).
 */
class AetherVpnService : VpnService() {
    // T215: every field below is written from the main thread (onStartCommand,
    // onRevoke, onDestroy) and from `worker`, sometimes while `lifecycleLock` is
    // held and sometimes before it is taken. Plain fields gave the worker thread
    // no guarantee of ever observing a new value, so `stopRequested` could be
    // missed for the whole life of a doomed tunnel. They are @Volatile now, and
    // every decision that combines two of them reads them inside the lock.
    @Volatile
    private var tun: ParcelFileDescriptor? = null

    @Volatile
    private var hevStarted = false

    @Volatile
    private var stopRequested = false

    private val lifecycleLock = Any()
    private val vpnGeneration = java.util.concurrent.atomic.AtomicLong(0)

    /** The generation handed to the most recent start request, main thread only. */
    @Volatile
    private var latestStartGen = NO_LISTENER

    @Volatile
    private var connectivityManager: ConnectivityManager? = null

    @Volatile
    private var networkCallback: ConnectivityManager.NetworkCallback? = null

    internal fun getVpnGeneration(): Long = vpnGeneration.get()

    /** Whether this service currently holds an open tun fd (T206's ground truth). */
    internal fun isTunnelUp(): Boolean = synchronized(lifecycleLock) { tun != null }

    override fun onCreate() {
        super.onCreate()
        current = this
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            vpnGeneration.incrementAndGet()
            // Disarm failure reporting: no worker was started with generation -1, so
            // a teardown that races an in-flight start cannot report an error the
            // user did not ask about.
            latestStartGen = NO_LISTENER
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
            val currentGen = vpnGeneration.incrementAndGet()
            latestStartGen = currentGen
            worker.execute {
                try {
                    check(socksPort in 1024..65535) { "VPN start missing valid SOCKS port" }
                    check(nativeLoaded) { "hev-socks5-tunnel native library unavailable" }
                    val established = establishTun(socksPort, currentGen)
                    if (established && ownsTunnel(currentGen)) {
                        mainHandler.post {
                            if (ownsTunnel(currentGen)) {
                                SessionController.getOrNull()?.onVpnEstablished()
                            }
                        }
                    }
                } catch (e: Exception) {
                    Log.e(TAG, "VPN establish failed: ${e.message}", e)
                    stopTunnel()
                    mainHandler.post {
                        // `stopTunnel()` above has already bumped `vpnGeneration`, so
                        // the token that proves "nobody superseded me" cannot be the
                        // generation: gating the report on it dropped every establish
                        // failure — including the loop-avoidance refusal — and left
                        // the session waiting for a tunnel that never existed.
                        if (reportsToUser(currentGen)) {
                            SessionController.getOrNull()?.onVpnFailed(e.message ?: "VPN establish failed")
                        }
                        stopSelf()
                    }
                } catch (e: UnsatisfiedLinkError) {
                    Log.e(TAG, "VPN native call failed: ${e.message}", e)
                    stopTunnel()
                    mainHandler.post {
                        if (reportsToUser(currentGen)) {
                            SessionController.getOrNull()?.onVpnFailed("VPN native library incompatible")
                        }
                        stopSelf()
                    }
                }
            }
        }
        return START_NOT_STICKY
    }

    /**
     * Whether the service the user last asked for is still the one started at
     * [gen]. Distinct from [ownsTunnel] on purpose: see the comment in the catch
     * blocks — a worker that failed has already invalidated its own token.
     */
    internal fun reportsToUser(gen: Long): Boolean = reportsToUser(gen, latestStartGen)

    /**
     * Whether the worker started at [gen] still owns the tunnel: no stop has been
     * requested and no newer start has superseded it. The service published this
     * rule inline twice (plus once per `mainHandler.post`) and the tests simulated
     * it against a local counter instead of calling it (T227).
     */
    internal fun ownsTunnel(gen: Long): Boolean =
        ownsTunnel(gen, vpnGeneration.get(), stopRequested)

    internal fun configureTunBuilder(): Builder {
        val builder = Builder()
            .setSession("Aether Next")
            .setMtu(MTU)
            .setBlocking(false)
            // /24 ensures 198.18.0.2 (MAPPED_DNS) is in the local subnet so Android DnsManager routes to it
            .addAddress(TUN_ADDR, 24)
            // Exclusively advertise MAPPED_DNS so all lookups hit mapdns fake-IP synthesis (and NODATA on AAAA).
            // Do NOT add public resolvers (1.1.1.1, 2606:4700:4700::1111) which cause netd to leak queries
            // or return real IPv6 addresses that bypass the tunnel on mobile data.
            .addDnsServer(MAPPED_DNS)
            .addRoute("0.0.0.0", 0)
            // /15 covers both 198.18.0.0/16 (interface & DNS) and 198.19.0.0/16 (mapdns fake-IP range)
            .addRoute("198.18.0.0", 15)
            // Trap all IPv6 inside the TUN interface with point-to-point host prefix 128 (prevent carrier bypass)
            .addAddress(TUN_ADDR_V6, 128)
            .addRoute("::", 0)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            try {
                builder.setMetered(false)
            } catch (e: Exception) {
                Log.w(TAG, "setMetered failed: ${e.message}")
            }
        }
        return builder
    }

    /**
     * Packages that must stay off the TUN. The engine child inherits this
     * package's uid, so excluding the package excludes the child's sockets too
     * (and is the only thing that can — see [LoopAvoidance]).
     */
    internal fun loopAvoidancePackages(): List<String> = listOf(packageName)

    internal fun registerUnderlyingNetworkCallbacks() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            try {
                val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
                connectivityManager = cm
                val callback = object : ConnectivityManager.NetworkCallback() {
                    override fun onAvailable(network: Network) {
                        Log.i(TAG, "underlying network available: $network")
                        try {
                            setUnderlyingNetworks(arrayOf(network))
                        } catch (e: Exception) {
                            Log.w(TAG, "setUnderlyingNetworks onAvailable failed: ${e.message}")
                        }
                    }

                    override fun onLost(network: Network) {
                        Log.i(TAG, "underlying network lost: $network")
                        try {
                            setUnderlyingNetworks(null)
                        } catch (e: Exception) {
                            Log.w(TAG, "setUnderlyingNetworks onLost failed: ${e.message}")
                        }
                    }

                    override fun onCapabilitiesChanged(
                        network: Network,
                        networkCapabilities: NetworkCapabilities,
                    ) {
                        try {
                            setUnderlyingNetworks(arrayOf(network))
                        } catch (e: Exception) {
                            Log.w(TAG, "setUnderlyingNetworks onCapabilitiesChanged failed: ${e.message}")
                        }
                    }
                }
                networkCallback = callback
                cm?.registerDefaultNetworkCallback(callback)
            } catch (e: Exception) {
                Log.w(TAG, "registerDefaultNetworkCallback failed: ${e.message}")
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP_MR1) {
                    try {
                        setUnderlyingNetworks(null)
                    } catch (_: Exception) {
                    }
                }
            }
        } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP_MR1) {
            try {
                setUnderlyingNetworks(null)
            } catch (e: Exception) {
                Log.w(TAG, "setUnderlyingNetworks failed: ${e.message}")
            }
        }
    }

    private fun establishTun(socksPort: Int, gen: Long): Boolean {
        synchronized(lifecycleLock) {
            if (stopRequested || gen != vpnGeneration.get()) return false
            // Idempotent: two onStartCommands can both observe tun == null before this
            // runs on the single worker thread; establishing twice would leak the first fd.
            if (tun != null) return true

            val builder = configureTunBuilder()
            // T202/T208: loop avoidance runs *inside* TunEstablishment, before
            // establish(), and a failure is thrown rather than swallowed — a tunnel
            // that carries the engine's own traffic is a blackhole, not a fallback.
            val established = TunEstablishment.establish(
                exempt = TunEstablishment.builderFor(builder),
                packages = loopAvoidancePackages(),
                openTun = { builder.establish() },
            )

            if (stopRequested || gen != vpnGeneration.get()) {
                try { established.close() } catch (_: Exception) {}
                return false
            }
            tun = established
            VpnTunnel.established(true, socksPort)

            registerUnderlyingNetworkCallbacks()

            val configPath = writeHevConfig(socksPort)
            Log.i(TAG, "starting hev tun2socks fd=${established.fd} socks=127.0.0.1:$socksPort conf=$configPath")
            TProxyStartService(configPath, established.fd)
            hevStarted = true
            Log.i(TAG, "VPN + hev-socks5-tunnel active")
            return true
        }
    }

    private fun writeHevConfig(socksPort: Int): String {
        val conf = File(noBackupFilesDir, "hev-socks5-tunnel.yml")
        // udp:udp — aether implements standard SOCKS5 UDP ASSOCIATE (not UDP-in-TCP).
        // mapdns — resolve names via SOCKS so apps do not depend on raw UDP DNS.
        // network: 198.19.0.0/16 — RFC 2544 benchmark unicast space, non-overlapping with TUN_ADDR (198.18.0.1) and MAPPED_DNS (198.18.0.2).
        // icmp: reject — immediately reject unrouteable / IPv6 flows with ECONNREFUSED/RST so Happy Eyeballs fails fast to IPv4.
        val yaml = """
            |tunnel:
            |  mtu: $MTU
            |  ipv4: $TUN_ADDR
            |  ipv6: '$TUN_ADDR_V6'
            |  icmp: 'reject'
            |socks5:
            |  port: $socksPort
            |  address: 127.0.0.1
            |  udp: 'udp'
            |mapdns:
            |  address: $MAPPED_DNS
            |  port: 53
            |  network: $MAPPED_NETWORK
            |  netmask: 255.255.0.0
            |  cache-size: 10000
            |misc:
            |  task-stack-size: 81920
            |  connect-timeout: 5000
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

    private fun stopTunnel() {
        synchronized(lifecycleLock) {
            vpnGeneration.incrementAndGet()
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
            VpnTunnel.established(false, -1)

            try {
                networkCallback?.let { cb ->
                    connectivityManager?.unregisterNetworkCallback(cb)
                }
            } catch (e: Exception) {
                Log.w(TAG, "unregisterNetworkCallback failed: ${e.message}")
            }
            networkCallback = null
            connectivityManager = null
        }
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
        if (current === this) current = null
        if (unexpected) {
            SessionController.getOrNull()?.onVpnFailed("VPN service stopped by system")
        } else {
            // The tunnel is closed and the fd released *now*: this is the ack the
            // session waits on before it is allowed to say "Ready" (T206).
            SessionController.getOrNull()?.onVpnStopped()
        }
        super.onDestroy()
    }

    companion object {
        private const val TAG = "AetherVpn"
        private const val CHANNEL = "aether_vpn"
        private const val NOTIF_ID = 43
        private const val MTU = 1280
        private const val TUN_ADDR = "198.18.0.1"
        // Unique local address for dual-stack IPv6 tunnel.
        private const val TUN_ADDR_V6 = "fd00:ae::1"
        private const val MAPPED_DNS = "198.18.0.2"
        // RFC 2544 benchmark range isolated from TUN_ADDR (198.18.0.1) and MAPPED_DNS (198.18.0.2)
        private const val MAPPED_NETWORK = "198.19.0.0"
        @Volatile
        private var nativeLoaded = false
        private val worker = Executors.newSingleThreadExecutor { r ->
            Thread(r, "aether-vpn-worker").apply { isDaemon = true }
        }
        private val mainHandler = Handler(Looper.getMainLooper())
        const val EXTRA_SOCKS_PORT = "socks_port"
        const val ACTION_STOP = "app.aethernext.VPN_STOP"

        /** A generation no worker can have: nobody is listening for a report. */
        private const val NO_LISTENER = -1L

        /** The live service, if any. @Volatile because the session reads it from `worker`. */
        @Volatile
        internal var current: AetherVpnService? = null

        /**
         * The rule the service applies before publishing any worker result — kept as
         * a pure function of the three values so it can be asserted directly
         * instead of against a test-local counter (T227).
         */
        internal fun ownsTunnel(gen: Long, currentGen: Long, stopRequested: Boolean): Boolean =
            !stopRequested && gen == currentGen

        /**
         * The failure-report rule. `NO_LISTENER` is what a STOP leaves behind, so a
         * teardown in flight silences the workers it invalidates.
         */
        internal fun reportsToUser(gen: Long, latestStartGen: Long): Boolean =
            gen != NO_LISTENER && gen == latestStartGen

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
        @androidx.annotation.Keep
        private external fun TProxyStartService(configPath: String, fd: Int)

        @JvmStatic
        @androidx.annotation.Keep
        private external fun TProxyStopService()

        @JvmStatic
        @androidx.annotation.Keep
        private external fun TProxyGetStats(): LongArray
    }
}
