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

    /**
     * Descriptors handed to the worker for a bounded close. While it is non-zero the
     * tunnel is not yet fully released, so no path may publish "there is no tunnel".
     */
    private val pendingCloses = java.util.concurrent.atomic.AtomicInteger(0)

    /** The generation handed to the most recent start request, main thread only. */
    @Volatile
    private var latestStartGen = NO_LISTENER

    @Volatile
    private var connectivityManager: ConnectivityManager? = null

    @Volatile
    private var networkCallback: ConnectivityManager.NetworkCallback? = null

    internal fun getVpnGeneration(): Long = vpnGeneration.get()

    /**
     * Whether this service currently holds an open tun fd (T206's ground truth).
     *
     * Deliberately a plain volatile read: `onRevoke` and the session's fail-closed
     * reconciliation both ask this question, and taking `lifecycleLock` here let a
     * teardown that is waiting on hev block the very call that was supposed to
     * notice the tunnel is gone.
     */
    internal fun isTunnelUp(): Boolean = tun != null

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
            // Do not *keep* a foreground service running for a stop — but a stop can
            // arrive as `startForegroundService` (that is the only form a backgrounded
            // app may send, and `SessionController.stopVpnService` escalates to it),
            // and Android answers a `startForegroundService` that never calls
            // `startForeground` with a crash. Take the notification, tear down, stop.
            try {
                startForegroundNotification()
            } catch (e: Exception) {
                Log.w(TAG, "stop path could not take the foreground notification: ${e.message}")
            }
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

    /**
     * Applies [TunConfig]'s plan. The plan itself — which address, which prefix,
     * which single DNS server — lives in [TunConfig] so it can be asserted without
     * a device; this function's only job is to hand it to Android.
     */
    internal fun configureTunBuilder(): Builder {
        val builder = Builder()
            .setSession(TunConfig.SESSION_NAME)
            .setMtu(TunConfig.MTU)
            .setBlocking(false)
        TunConfig.addressPlan().forEach { (addr, prefix) -> builder.addAddress(addr, prefix) }
        TunConfig.dnsPlan().forEach { builder.addDnsServer(it) }
        TunConfig.routePlan().forEach { (target, prefix) -> builder.addRoute(target, prefix) }

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

    /**
     * The capability probe [UnderlyingNetworks] filters with. A network this
     * service created carries `NET_CAPABILITY_VPN`; adopting it as our own
     * underlying network tells the tunnel to carry itself.
     *
     * Fails closed: a network whose capabilities cannot be read is not one we
     * publish.
     */
    private fun hasVpnCapability(network: Network): Boolean {
        if (android.os.Build.VERSION.SDK_INT < android.os.Build.VERSION_CODES.TIRAMISU) {
            // Below API 33 the platform exposes no bit to read, so the tunnel
            // cannot be identified by capability. Refusing to adopt is the safe
            // answer: the failure we are guarding against is handing the tunnel
            // its own network to carry.
            return true
        }
        return try {
            connectivityManager?.getNetworkCapabilities(network)
                ?.hasCapability(NET_CAPABILITY_VPN) == true
        } catch (e: Exception) {
            Log.w(TAG, "getNetworkCapabilities failed for $network: ${e.message}")
            true
        }
    }

    /** Publish [network] as the underlying network unless it is our own tunnel. */
    private fun publishUnderlyingNetwork(network: Network, where: String) {
        val adopted = UnderlyingNetworks.pick(listOf(network), ::hasVpnCapability)
        val arg = UnderlyingNetworks.toUnderlyingArg(adopted) { it.toTypedArray() }
        if (arg == null) {
            Log.i(TAG, "$where: not adopting $network — it is a VPN network (ours)")
            return
        }
        try {
            setUnderlyingNetworks(arg)
        } catch (e: Exception) {
            Log.w(TAG, "setUnderlyingNetworks $where failed: ${e.message}")
        }
    }

    internal fun registerUnderlyingNetworkCallbacks() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            try {
                val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
                connectivityManager = cm
                val callback = object : ConnectivityManager.NetworkCallback() {
                    override fun onAvailable(network: Network) {
                        Log.i(TAG, "underlying network available: $network")
                        publishUnderlyingNetwork(network, "onAvailable")
                    }

                    override fun onLost(network: Network) {
                        Log.i(TAG, "underlying network lost: $network")
                        // Only a network we were allowed to adopt can be worth
                        // clearing; losing our own VPN network is not an outage.
                        if (hasVpnCapability(network)) return
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
                        publishUnderlyingNetwork(network, "onCapabilitiesChanged")
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
            tunSocksPort = socksPort
            // `TProxyGetStats()` is zeroed on every hev entry, so the baseline can only
            // be taken after the start returned — a sample from before it is not a
            // baseline, it is a different session's counters.
            startLivenessWatchdog()
            Log.i(TAG, "VPN + hev-socks5-tunnel active")
            return true
        }
    }

    // ─── data-path liveness (T203/T209, wired) ────────────────────────────────

    /**
     * The window tracker behind the watchdog. One per service instance; [reset] is
     * called for every tunnel, so a supervised restart does not inherit the streaks
     * of the tunnel that just died.
     */
    private val liveness = LivenessTracker()

    @Volatile
    private var livenessPoll: java.util.concurrent.ScheduledFuture<*>? = null

    /** The SOCKS port the running tunnel forwards to — what a restart re-uses. */
    @Volatile
    private var tunSocksPort = -1

    private fun startLivenessWatchdog() {
        cancelLivenessWatchdog()
        liveness.reset()
        if (!nativeLoaded) return
        try {
            liveness.baseline(TProxyGetStats(), elapsedRealtime())
        } catch (e: UnsatisfiedLinkError) {
            Log.w(TAG, "hev stats unavailable, liveness watchdog disabled: ${e.message}")
            return
        } catch (e: Exception) {
            Log.w(TAG, "liveness baseline failed: ${e.message}")
            return
        }
        livenessPoll = worker.scheduleWithFixedDelay(
            { pollLiveness() },
            WINDOW_MS,
            WINDOW_MS,
            java.util.concurrent.TimeUnit.MILLISECONDS,
        )
    }

    private fun cancelLivenessWatchdog() {
        livenessPoll?.cancel(false)
        livenessPoll = null
    }

    /** Monotonic clock, with a wall-clock fallback so a stubbed `SystemClock` cannot stall the window. */
    private fun elapsedRealtime(): Long = try {
        android.os.SystemClock.elapsedRealtime()
    } catch (_: Throwable) {
        System.currentTimeMillis()
    }

    /**
     * One poll of hev's own counters.
     *
     * This is the only thing in the app that can tell "the interface is up" from
     * "the interface is carrying anything", and until now nothing asked: the fd was
     * the whole truth, so a QUIC socket left bound to a vanished interface produced
     * a green badge over a total blackhole. A dead verdict costs one restart from
     * [LivenessTracker]'s budget; a spent budget is published to the user as
     * [RECONNECT_REQUIRED] instead of being retried forever.
     */
    private fun pollLiveness() {
        try {
            if (stopRequested || tun == null) return
            val sample = try {
                TProxyGetStats()
            } catch (e: UnsatisfiedLinkError) {
                Log.w(TAG, "liveness poll disabled: ${e.message}")
                cancelLivenessWatchdog()
                return
            }
            val decision = liveness.onSample(sample, elapsedRealtime(), probeFailed = foregroundProbeFailed())
            if (decision !is LivenessDecision.Alive) {
                Log.w(TAG, "tunnel liveness: $decision (frozen=${liveness.frozenWindowCount()} silent=${liveness.silentWindowCount()})")
            }
            if (!decision.isDead) return
            when (val plan = liveness.consumeRestart()) {
                is RestartPlan.RetryAfter -> restartTunnel(plan.delayMs, plan.attempt)
                RestartPlan.GiveUp -> {
                    cancelLivenessWatchdog()
                    stopTunnel(blocking = false)
                    SessionController.getOrNull()?.onVpnFailed(RECONNECT_REQUIRED)
                }
            }
        } catch (e: Exception) {
            // A watchdog that dies quietly is worse than no watchdog: keep polling and
            // say that this window was lost.
            Log.w(TAG, "liveness poll failed: ${e.message}")
        }
    }

    /**
     * Did the device itself lose the network the tunnel rides on? Used to gate the
     * fully-silent verdict, which an idle device also produces.
     */
    private fun foregroundProbeFailed(): Boolean {
        val cm = connectivityManager ?: return false
        return try {
            cm.allNetworks.none { network ->
                val caps = cm.getNetworkCapabilities(network) ?: return@none false
                !caps.hasCapability(NET_CAPABILITY_VPN) &&
                    caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            }
        } catch (e: Exception) {
            false
        }
    }

    private fun restartTunnel(delayMs: Long, attempt: Int) {
        val port = tunSocksPort
        if (port !in 1024..65535) {
            SessionController.getOrNull()?.onVpnFailed(RECONNECT_REQUIRED)
            return
        }
        Log.w(TAG, "data path dead: supervised restart #$attempt in ${delayMs}ms")
        SessionController.getOrNull()?.onVpnRestartScheduled(attempt)
        worker.schedule({
            if (stopRequested || tun != null) return@schedule
            stopTunnel()
            val gen = vpnGeneration.incrementAndGet()
            latestStartGen = gen
            try {
                if (establishTun(port, gen) && ownsTunnel(gen)) {
                    mainHandler.post { SessionController.getOrNull()?.onVpnEstablished() }
                }
            } catch (e: Exception) {
                Log.e(TAG, "supervised restart failed: ${e.message}", e)
                stopTunnel()
                mainHandler.post {
                    if (reportsToUser(gen)) {
                        SessionController.getOrNull()?.onVpnFailed(e.message ?: RECONNECT_REQUIRED)
                    }
                }
            }
        }, delayMs, java.util.concurrent.TimeUnit.MILLISECONDS)
    }

    private fun writeHevConfig(socksPort: Int): String {
        val conf = File(noBackupFilesDir, "hev-socks5-tunnel.yml")
        FileOutputStream(conf, false).use { it.write(TunConfig.hevYaml(socksPort).toByteArray(Charsets.UTF_8)) }
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
                // Android's documented type for a VPN service. `specialUse` is the
                // "everything else" bucket and asks for a justification Play reviewers
                // reject for a VpnService; `systemExempted` is the declared one.
                ServiceInfo.FOREGROUND_SERVICE_TYPE_SYSTEM_EXEMPTED,
            )
        } else {
            startForeground(NOTIF_ID, n)
        }
    }

    /**
     * Tear the tunnel down.
     *
     * The descriptor may only be closed once hev's threads are out of it, and that
     * was previously "guaranteed" by `Thread.sleep(150)` — a guess that cost the
     * main thread 150 ms on every `onRevoke` and still left a SIGSEGV window when
     * hev was slow. It now goes through [HevStop], which waits for the real
     * acknowledgement inside a bounded budget (T214).
     *
     * With [blocking] false the caller returns immediately: `onRevoke` runs on the
     * main thread, and Android's Quick Settings tap used to ANR there (T2xx). The
     * `tun` reference is cleared under the lock either way, so [isTunnelUp] and the
     * session's fail-closed reconciliation stop claiming a tunnel right away; only
     * the descriptor close moves to the worker.
     */
    private fun stopTunnel(blocking: Boolean = true) {
        val fd: ParcelFileDescriptor?
        val mustStopHev: Boolean
        synchronized(lifecycleLock) {
            vpnGeneration.incrementAndGet()
            cancelLivenessWatchdog()
            fd = tun
            tun = null
            mustStopHev = hevStarted
            hevStarted = false
            tunSocksPort = -1
            unregisterNetworkCallbacksLocked()
        }
        if (!mustStopHev) {
            releaseAfterClose(fd, ownsPendingSlot = false)
            return
        }
        if (blocking) {
            reportHevStop(HevStop.stopAndAwait(stop = { TProxyStopService() }))
            releaseAfterClose(fd, ownsPendingSlot = false)
            return
        }
        pendingCloses.incrementAndGet()
        worker.execute {
            try {
                reportHevStop(HevStop.stopAndAwait(stop = { TProxyStopService() }))
            } finally {
                releaseAfterClose(fd, ownsPendingSlot = true)
            }
        }
    }

    private fun reportHevStop(outcome: HevStopOutcome) {
        when (outcome) {
            is HevStopOutcome.TimedOut -> Log.e(
                TAG,
                "hev never acknowledged the stop (waited ${outcome.waitedMs}ms); closing the " +
                    "descriptor anyway so the device is not left without an owner",
            )

            is HevStopOutcome.Failed -> Log.e(TAG, "hev stop call failed: ${outcome.reason}")
            HevStopOutcome.Acknowledged -> Unit
        }
    }

    /**
     * Close [fd] and publish "there is no tunnel". The publish is withheld while
     * another close is still in flight, so a non-blocking revoke cannot let the
     * session announce "Ready" over a descriptor its worker has not closed yet.
     */
    private fun releaseAfterClose(fd: ParcelFileDescriptor?, ownsPendingSlot: Boolean) {
        try {
            fd?.close()
        } catch (_: Exception) {
        }
        if (ownsPendingSlot) pendingCloses.decrementAndGet()
        if (pendingCloses.get() <= 0) VpnTunnel.established(false, -1)
    }

    private fun unregisterNetworkCallbacksLocked() {
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

    /**
     * Android owns the revocation: it can arrive while a start is in flight, on the
     * main thread, with no second chance. Nothing here may wait for hev.
     */
    override fun onRevoke() {
        stopRequested = true
        stopTunnel(blocking = false)
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
        /**
         * `NetworkCapabilities.NET_CAPABILITY_VPN` became public API only at level
         * 33, and its value is stable, so the number is bound here rather than
         * through the symbol the compile SDK may not declare. Every read is
         * guarded by the SDK_INT check in [hasVpnCapability].
         */
        private const val NET_CAPABILITY_VPN = 33
        private const val TAG = "AetherVpn"
        private const val CHANNEL = "aether_vpn"
        private const val NOTIF_ID = 43
        @Volatile
        private var nativeLoaded = false
        private val worker = Executors.newSingleThreadScheduledExecutor { r ->
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

        /**
         * hev's own packet counters: `[tx_packets, tx_bytes, rx_packets, rx_bytes]`
         * as seen from the tun, zeroed on every `hev_socks5_tunnel_main()` entry.
         *
         * Declared, called from [pollLiveness], and kept `@Keep` because hev-jni binds
         * the whole method table of this class: deleting an unused sibling here is not
         * a cosmetic change on a device.
         */
        @JvmStatic
        @androidx.annotation.Keep
        private external fun TProxyGetStats(): LongArray
    }
}
