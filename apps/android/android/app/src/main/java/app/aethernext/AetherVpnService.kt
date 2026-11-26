package app.aethernext

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.ParcelFileDescriptor
import android.os.PowerManager
import android.util.Log
import androidx.core.app.NotificationCompat
import androidx.core.app.ServiceCompat
import java.io.IOException
import java.net.InetSocketAddress
import java.net.NoRouteToHostException
import java.net.Socket
import java.net.SocketTimeoutException
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
    private var tunnelWakeLock: PowerManager.WakeLock? = null

    @Volatile
    private var activeUnderlyingNetwork: Network? = null

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

    @Volatile
    private var vpnProbeCallback: ConnectivityManager.NetworkCallback? = null

    /**
     * The [Network] the platform created for *this* tunnel, when the platform lets
     * us identify it. [probeTunnelDataPath] binds its socket to it, which is the
     * only way a check from this process can be made to travel through the tunnel:
     * loop avoidance excludes our uid, so an unbound probe socket would sail straight
     * past the TUN and report a blackhole as healthy.
     *
     * Null on releases that expose no readable VPN capability — there the through-
     * tunnel probe is `Unavailable` rather than a guess.
     */
    @Volatile
    private var tunnelNetwork: Network? = null

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
        if (intent?.action == ACTION_DISCONNECT) {
            try {
                startForegroundNotification()
            } catch (_: Exception) {
            }
            worker.execute {
                SessionController.getOrNull()?.disconnect()
                mainHandler.post { stopSelfResult(startId) }
            }
            return Service.START_NOT_STICKY
        }
        if (intent?.action == ACTION_STOP) {
            vpnGeneration.incrementAndGet()
            latestStartGen = NO_LISTENER
            stopRequested = true
            try {
                startForegroundNotification()
            } catch (e: Exception) {
                Log.w(TAG, "stop path could not take the foreground notification: ${e.message}")
            }
            worker.execute {
                stopTunnel()
                mainHandler.post { stopSelfResult(startId) }
            }
            return ServiceRestartPolicy.startCommandFor(
                ServiceRestartPolicy.decide(
                    role = ServiceRole.VpnTunnel,
                    redelivered = (flags and START_FLAG_REDELIVERY) != 0,
                    userAskedToStop = true,
                ),
            )
        }
        val isAlwaysOnStart = intent?.action == VpnService.SERVICE_INTERFACE
        if (intent == null || (flags and START_FLAG_REDELIVERY) != 0 || isAlwaysOnStart) {
            val verdict = ServiceRestartPolicy.decide(
                role = ServiceRole.VpnTunnel,
                redelivered = true,
                userAskedToStop = stopRequested,
                tunnelHasLivePath = SessionController.getOrNull()?.let { it.runner.isRunning() } == true,
                consentValid = vpnConsentStillValid(),
                savedStateValid = savedSessionStateUsable(),
            )
            try {
                startForegroundNotification(
                    if (verdict == StartAction.Redeliver || !alwaysOnActive()) {
                        getString(R.string.notif_vpn)
                    } else {
                        NOTIF_BLOCKED
                    },
                )
            } catch (e: Exception) {
                Log.w(TAG, "redelivered start could not take the foreground notification: ${e.message}")
            }
            if (verdict == StartAction.Redeliver) {
                Log.i(TAG, "restart policy: the session this tunnel belongs to is still live, re-establishing")
                worker.execute {
                    try {
                        stopRequested = false
                        val port = SessionController.getOrNull()?.let { it.getSettings().socksPort } ?: -1
                        if (port in 1024..65535) {
                            val gen = vpnGeneration.incrementAndGet()
                            latestStartGen = gen
                            if (establishTun(port, gen) && ownsTunnel(gen)) {
                                mainHandler.post { SessionController.getOrNull()?.onVpnEstablished() }
                            } else {
                                mainHandler.post { stopSelfResult(startId) }
                            }
                        } else {
                            mainHandler.post { stopSelfResult(startId) }
                        }
                    } catch (t: Throwable) {
                        Log.e(TAG, "redelivered establish failed: ${t.message}", t)
                        stopTunnel()
                        mainHandler.post { stopSelfResult(startId) }
                    }
                }
                return ServiceRestartPolicy.startCommandFor(StartAction.Redeliver)
            }
            Log.e(TAG, "restart policy: $verdict — ${SERVICE_KILLED_BY_OS}")
            SessionController.getOrNull()?.emitLog("VPN service $SERVICE_KILLED_BY_OS")
            stopRequested = true
            worker.execute {
                stopTunnel()
                mainHandler.post { stopSelfResult(startId) }
            }
            return ServiceRestartPolicy.startCommandFor(verdict)
        }
        try {
            startForegroundNotification()
        } catch (e: Exception) {
            Log.e(TAG, "startForeground failed: ${e.message}", e)
            SessionController.getOrNull()?.onVpnFailed("VPN foreground start blocked: ${e.message}")
            stopSelfResult(startId)
            return ServiceRestartPolicy.startCommandFor(StartAction.KeepAliveOnly)
        }
        stopRequested = false
        val socksPort = intent.getIntExtra(EXTRA_SOCKS_PORT, -1)
        val currentGen = vpnGeneration.incrementAndGet()
        latestStartGen = currentGen
        worker.execute {
            try {
                if (tun != null) {
                    stopTunnel()
                }
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
                    if (reportsToUser(currentGen)) {
                        SessionController.getOrNull()?.onVpnFailed(e.message ?: "VPN establish failed")
                    }
                    stopSelfResult(startId)
                }
            } catch (e: UnsatisfiedLinkError) {
                Log.e(TAG, "VPN native call failed: ${e.message}", e)
                stopTunnel()
                mainHandler.post {
                    if (reportsToUser(currentGen)) {
                        SessionController.getOrNull()?.onVpnFailed("VPN native library incompatible")
                    }
                    stopSelfResult(startId)
                }
            }
        }
        return ServiceRestartPolicy.startCommandFor(
            ServiceRestartPolicy.decide(
                role = ServiceRole.VpnTunnel,
                redelivered = false,
                userAskedToStop = stopRequested,
            ),
        )
    }

    /**
     * Is the VPN permission this session needs still granted? `prepare()` returns
     * null without a consent sheet when it is. A thrown answer counts as "no": the
     * conservative reading of a question the platform would not answer.
     */
    private fun vpnConsentStillValid(): Boolean = try {
        VpnService.prepare(this) == null
    } catch (e: Exception) {
        Log.w(TAG, "VpnService.prepare failed: ${e.message}")
        false
    }

    /**
     * Whether the saved state describes a session this service could resume: full-
     * device routing with a port the engine can be pointed at, and a settings blob
     * that was neither quarantined as corrupt nor replaced by defaults.
     */
    private fun savedSessionStateUsable(): Boolean {
        val store = SettingsStore(this)
        val s = store.load()
        return store.settingsAreHealthy() &&
            s.routingMode == "tun" &&
            s.socksPort in 1024..65535
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
        // Omit setMetered(false) so Android inherits meteredness from underlying networks.
        return builder
    }

    internal fun loopAvoidancePackages(): List<String> = listOf(packageName)

    private fun hasVpnCapability(network: Network): Boolean {
        return try {
            val caps = connectivityManager?.getNetworkCapabilities(network)
            caps != null && classifiesAsVpn(caps::hasTransport, caps::hasCapability)
        } catch (e: Exception) {
            Log.w(TAG, "getNetworkCapabilities failed for $network: ${e.message}")
            true
        }
    }

    private fun isVpnNetwork(network: Network): Boolean {
        return try {
            val caps = connectivityManager?.getNetworkCapabilities(network)
            caps != null && classifiesAsVpn(caps::hasTransport, caps::hasCapability)
        } catch (e: Exception) {
            Log.w(TAG, "isVpnNetwork($network) failed: ${e.message}")
            false
        }
    }

    private fun publishUnderlyingNetwork(network: Network, where: String) {
        if (isVpnNetwork(network)) {
            return
        }
        val adopted = UnderlyingNetworks.pick(listOf(network), ::hasVpnCapability)
        val arg = UnderlyingNetworks.toUnderlyingArg(adopted) { it.toTypedArray() }
        if (arg == null) {
            Log.i(TAG, "$where: not adopting $network — it is a VPN network (ours)")
            return
        }
        try {
            activeUnderlyingNetwork = network
            setUnderlyingNetworks(arg)
        } catch (e: Exception) {
            Log.w(TAG, "setUnderlyingNetworks $where failed: ${e.message}")
        }
    }

    internal fun registerUnderlyingNetworkCallbacks() {
        try {
            val callbackGeneration = vpnGeneration.get()
            val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
            connectivityManager = cm
            val callback = object : ConnectivityManager.NetworkCallback() {
                override fun onAvailable(network: Network) {
                    synchronized(lifecycleLock) {
                        if (!ownsTunnel(callbackGeneration)) return
                        Log.i(TAG, "underlying network available: $network")
                        publishUnderlyingNetwork(network, "onAvailable")
                    }
                }

                override fun onLost(network: Network) {
                    synchronized(lifecycleLock) {
                        if (!ownsTunnel(callbackGeneration)) return
                        Log.i(TAG, "underlying network lost: $network")
                        if (tunnelNetwork === network) tunnelNetwork = null
                        if (hasVpnCapability(network)) return
                        if (activeUnderlyingNetwork != null && activeUnderlyingNetwork != network) {
                            return
                        }
                        activeUnderlyingNetwork = null
                        try {
                            setUnderlyingNetworks(null)
                        } catch (e: Exception) {
                            Log.w(TAG, "setUnderlyingNetworks onLost failed: ${e.message}")
                        }
                    }
                }

                override fun onCapabilitiesChanged(
                    network: Network,
                    networkCapabilities: NetworkCapabilities,
                ) {
                    synchronized(lifecycleLock) {
                        if (!ownsTunnel(callbackGeneration)) return
                        publishUnderlyingNetwork(network, "onCapabilitiesChanged")
                    }
                }
            }
            networkCallback = callback
            cm?.registerDefaultNetworkCallback(callback)

                // The default callback above cannot discover a VPN from an app
                // excluded by addDisallowedApplication. Request VPN transports
                // explicitly and remove NOT_VPN, which NetworkRequest adds by
                // default. On Android 12+ include networks for other UIDs because
                // this VPN deliberately does not apply to our own UID.
                val vpnRequest = NetworkRequest.Builder()
                    .addTransportType(NetworkCapabilities.TRANSPORT_VPN)
                    .removeCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
                    .apply {
                        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                            setIncludeOtherUidNetworks(true)
                        }
                    }
                    .build()
                val probeCallback = object : ConnectivityManager.NetworkCallback() {
                    override fun onAvailable(network: Network) {
                        // Wait for capabilities so a foreign VPN is never mistaken
                        // for the tunnel this service owns.
                    }

                    override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) {
                        synchronized(lifecycleLock) {
                            if (!ownsTunnel(callbackGeneration)) return
                            val owned = caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN) &&
                                (Build.VERSION.SDK_INT < Build.VERSION_CODES.R ||
                                    caps.ownerUid == android.os.Process.myUid())
                            if (owned) {
                                tunnelNetwork = network
                                Log.i(TAG, "own VPN network available for data-path probe: $network")
                            } else if (tunnelNetwork == network) {
                                tunnelNetwork = null
                            }
                            Unit
                        }
                    }

                    override fun onLost(network: Network) {
                        synchronized(lifecycleLock) {
                            if (!ownsTunnel(callbackGeneration)) return
                            if (tunnelNetwork == network) tunnelNetwork = null
                            Unit
                        }
                    }
                }
                cm?.registerNetworkCallback(vpnRequest, probeCallback)
                vpnProbeCallback = probeCallback
            } catch (e: Exception) {
                Log.w(TAG, "registerDefaultNetworkCallback failed: ${e.message}")
                try {
                    setUnderlyingNetworks(null)
                } catch (_: Exception) {
                }
            }
    }

    /**
     * Open the TUN and hand its descriptor to hev.
     *
     * [inheritAttempts] carries the supervised-restart budget across the rebuild: a
     * replacement tunnel that started from a fresh budget turned the bounded retry
     * into an endless loop the moment the restart itself began to work, because every
     * restart re-entered this function. It is `true` only for a restart of a session
     * the user already started; a fresh `onStartCommand` resets to zero.
     */
    private fun establishTun(socksPort: Int, gen: Long, inheritAttempts: Boolean = false): Boolean {
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
            acquireTunnelWakeLock()

            registerUnderlyingNetworkCallbacks()

            val configPath = writeHevConfig(socksPort)
            Log.i(TAG, "starting hev tun2socks fd=${established.fd} socks=127.0.0.1:$socksPort conf=$configPath")
            TProxyStartService(configPath, established.fd)
            hevStarted = true
            tunSocksPort = socksPort
            // `TProxyGetStats()` is zeroed on every hev entry, so the baseline can only
            // be taken after the start returned — a sample from before it is not a
            // baseline, it is a different session's counters.
            startLivenessWatchdog(inheritAttempts)
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

    private fun startLivenessWatchdog(inheritAttempts: Boolean = false) {
        cancelLivenessWatchdog()
        // `reset` clears the streaks — a fresh tunnel has no history — and the flag
        // decides whether the *budget* is fresh too. A supervised restart must not
        // inherit a clean slate for the counter that bounds it.
        liveness.reset(attempt = if (inheritAttempts) liveness.attempt else 0)
        if (!nativeLoaded) return
        try {
            val stats = synchronized(lifecycleLock) {
                if (!hevStarted) return
                TProxyGetStats()
            }
            liveness.baseline(stats, elapsedRealtime())
        } catch (e: UnsatisfiedLinkError) {
            Log.w(TAG, "hev stats unavailable, liveness watchdog disabled: ${e.message}")
            return
        } catch (e: Exception) {
            Log.w(TAG, "liveness baseline failed: ${e.message}")
            return
        }
        livenessPoll = probeExecutor.scheduleWithFixedDelay(
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

    private fun elapsedRealtime(): Long = try {
        android.os.SystemClock.elapsedRealtime()
    } catch (_: Throwable) {
        System.currentTimeMillis()
    }

    private fun pollLiveness() {
        try {
            val sample = synchronized(lifecycleLock) {
                if (stopRequested || tun == null || !hevStarted) return
                try {
                    TProxyGetStats()
                } catch (e: UnsatisfiedLinkError) {
                    Log.w(TAG, "liveness poll disabled: ${e.message}")
                    cancelLivenessWatchdog()
                    return
                }
            }
            val probe = if (shouldProbeDataPath(liveness.silentWindowCount())) probeTunnelDataPath() else null
            if (stopRequested || tun == null) return
            val verdict = probe?.let { verdictForSilentPath(underlyingNetworkAvailable(), it) }
            val decision = liveness.onSample(
                sample,
                elapsedRealtime(),
                probeFailed = verdict == SilentPathVerdict.DeadBlackhole,
            )
            if (decision !is LivenessDecision.Alive) {
                Log.w(TAG, "tunnel liveness: $decision (frozen=${liveness.frozenWindowCount()} " +
                    "silent=${liveness.silentWindowCount()} probe=$probe path=$verdict)")
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
            Log.w(TAG, "liveness poll failed: ${e.message}")
        }
    }

    /**
     * Does the device itself have a network to carry traffic?
     *
     * This is *not* a data-path check and must never be read as one (item 7): it asks
     * the radio, not the tunnel, and a tunnel that blackholes rides a network that
     * answers this happily. It survives as one input to [verdictForSilentPath], whose
     * only job is to keep "the network is gone" (not the tunnel's fault) apart from
     * "the network is up and nothing comes back through the TUN" (the tunnel's fault).
     */
    private fun underlyingNetworkAvailable(): Boolean {
        val cm = connectivityManager ?: return false
        return try {
            cm.allNetworks.any { network ->
                val caps = cm.getNetworkCapabilities(network) ?: return@any false
                !classifiesAsVpn(caps::hasTransport, caps::hasCapability) &&
                    caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            }
        } catch (e: Exception) {
            Log.w(TAG, "underlyingNetworkAvailable failed: ${e.message}")
            false
        }
    }

    /**
     * Attempt one bounded connect *through* the tunnel.
     *
     * Binding to [tunnelNetwork] is what makes this a data-path check rather than a
     * loopback one: this process's own uid is excluded from the TUN by loop avoidance,
     * so an unbound socket would reach the peer over the underlying network and call a
     * dead tunnel healthy. When there is no tunnel network to bind to, the probe
     * reports [PathProbe.Unavailable] and nothing is invented.
     */
    private fun probeTunnelDataPath(): PathProbe = probeIndependentTargets { target ->
        probeThroughTunnel(
            target = target,
            timeoutMs = PROBE_TIMEOUT_MS,
            bindToTunnel = { socket ->
                val network = tunnelNetwork
                if (network == null) {
                    false
                } else {
                    try {
                        network.bindSocket(socket)
                        true
                    } catch (e: Exception) {
                        Log.w(TAG, "probe socket could not be bound to the tunnel: ${e.message}")
                        false
                    }
                }
            },
            note = { message -> Log.i(TAG, "VPN data-path probe to $target: $message") },
        )
    }

    /**
     * This service as the [TunnelRestartOps] the supervised restart works through.
     *
     * A restart is the one decision in this class that has to be assertable without a
     * device — "close the dead descriptor, then rebuild" is exactly the shape the bug
     * was — so the sequence lives in [runSupervisedRestart] over this seam and the
     * service supplies nothing but its own fields.
     */
    internal fun restartOps(): TunnelRestartOps = object : TunnelRestartOps {
        override fun tunnelOpen(): Boolean = tun != null
        override fun stopRequested(): Boolean = this@AetherVpnService.stopRequested
        override fun generation(): Long = vpnGeneration.get()
        override fun closeTunnel() {
            this@AetherVpnService.stopTunnel()
        }

        override fun establish(port: Int, gen: Long): Boolean {
            latestStartGen = gen
            return establishTun(port, gen, inheritAttempts = true)
        }

        override fun reportEstablished(gen: Long) {
            mainHandler.post {
                if (ownsTunnel(gen)) SessionController.getOrNull()?.onVpnEstablished()
            }
        }

        override fun reportFailed(gen: Long, reason: String) {
            mainHandler.post {
                if (reportsToUser(gen)) {
                    SessionController.getOrNull()?.onVpnFailed(reason)
                }
            }
        }
    }

    private fun restartTunnel(delayMs: Long, attempt: Int) {
        // The port this session's engine is actually listening on, deliberately not
        // re-read from settings: `establishTun` writes the userspace tunnel's SOCKS
        // target, so a restart has to point at the running listener. Loading the
        // current settings instead would re-point the tunnel at a port nothing is
        // bound to the moment a save changed it, and a supervised restart would turn
        // a dead path into a blackhole with a green badge.
        val port = tunSocksPort
        if (port !in 1024..65535) {
            SessionController.getOrNull()?.onVpnFailed(RECONNECT_REQUIRED)
            return
        }
        // The token this restart is armed against. It is the generation of the tunnel
        // that was just judged dead, and [runSupervisedRestart] refuses to act once
        // anything else has torn that session down — the callback fires up to 30 s
        // later, and a stop requested in between must not be revived.
        val armedGen = vpnGeneration.get()
        Log.w(TAG, "data path dead: supervised restart #$attempt in ${delayMs}ms")
        SessionController.getOrNull()?.onVpnRestartScheduled(attempt)
        worker.schedule({
            runSupervisedRestart(armedGen, port, restartOps())
        }, delayMs, java.util.concurrent.TimeUnit.MILLISECONDS)
    }

    private fun writeHevConfig(socksPort: Int): String {
        val conf = File(noBackupFilesDir, "hev-socks5-tunnel.yml")
        val tmp = File(noBackupFilesDir, "hev-socks5-tunnel.${System.nanoTime()}.tmp")
        FileOutputStream(tmp, false).use { it.write(TunConfig.hevYaml(socksPort).toByteArray(Charsets.UTF_8)) }
        try {
            tmp.setReadable(true, true)
            tmp.setWritable(true, true)
        } catch (_: Exception) {
        }
        if (!tmp.renameTo(conf)) {
            FileOutputStream(conf, false).use { it.write(TunConfig.hevYaml(socksPort).toByteArray(Charsets.UTF_8)) }
            tmp.delete()
        }
        return conf.absolutePath
    }

    /**
     * Whether Android started this instance as an always-on VPN.
     *
     * `isAlwaysOn()` arrived in API 29, below the app's supported floor there is
     * no way to ask, and a failed answer is reported as "no": a wrong "yes" would
     * put a blocked-connections sentence on an ordinary tunnel notification.
     */
    private fun alwaysOnActive(): Boolean {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) return false
        return try {
            isAlwaysOn()
        } catch (e: Exception) {
            Log.w(TAG, "isAlwaysOn failed: ${e.message}")
            false
        }
    }

    private fun startForegroundNotification(text: String = getString(R.string.notif_vpn)) {
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
        val disconnectPending = PendingIntent.getService(
            this,
            1,
            Intent(this, AetherVpnService::class.java).apply { action = ACTION_DISCONNECT },
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val n: Notification = NotificationCompat.Builder(this, CHANNEL)
            .setContentTitle(getString(R.string.app_name))
            .setContentText(text)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentIntent(open)
            .addAction(0, getString(R.string.action_disconnect), disconnectPending)
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
    /**
     * Hold the CPU while the tunnel carries traffic.
     *
     * QUIC's idle and keep-alive deadlines are clock readings compared on a timer
     * this process does not control. Under doze the timer stops firing, the peer
     * ages the connection out, and the session is gone while the interface still
     * says connected — the same lie the tunnel-coherence check exists to catch on
     * the desktop. A partial wake lock keeps the CPU and not the screen, is taken
     * only with a live tun and released the moment it comes down, and carries a
     * 12 h cap so a code path that leaks it cannot drain a phone overnight.
     */
    private fun acquireTunnelWakeLock() {
        // Bounded 60s establish lock instead of holding CPU awake continuously for 12h.
        if (tunnelWakeLock?.isHeld == true) return
        val manager = getSystemService(Context.POWER_SERVICE) as PowerManager
        tunnelWakeLock = manager.newWakeLock(
            PowerManager.PARTIAL_WAKE_LOCK,
            "aether:tunnel",
        ).apply {
            setReferenceCounted(false)
            acquire(60_000L)
        }
    }

    private fun releaseTunnelWakeLock() {
        val lock = tunnelWakeLock
        tunnelWakeLock = null
        try {
            if (lock?.isHeld == true) lock.release()
        } catch (_: Exception) {
        }
    }

    private fun stopTunnel(blocking: Boolean = true) {
        val fd: ParcelFileDescriptor?
        val mustStopHev: Boolean
        synchronized(lifecycleLock) {
            releaseTunnelWakeLock()
            vpnGeneration.incrementAndGet()
            cancelLivenessWatchdog()
            activeUnderlyingNetwork = null
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

    private fun releaseAfterClose(fd: ParcelFileDescriptor?, ownsPendingSlot: Boolean) {
        try {
            fd?.close()
        } catch (_: Exception) {
        }
        if (ownsPendingSlot) pendingCloses.decrementAndGet()
        if (pendingCloses.get() <= 0) {
            VpnTunnel.established(false, -1)
            SessionController.getOrNull()?.onVpnStopped()
        }
    }

    private fun unregisterNetworkCallbacksLocked() {
        val cm = connectivityManager
        for (callback in listOfNotNull(networkCallback, vpnProbeCallback)) {
            try {
                cm?.unregisterNetworkCallback(callback)
            } catch (e: Exception) {
                // An exception from one callback must not leave the other
                // registered. Both registrations are independent OS resources.
                Log.w(TAG, "unregisterNetworkCallback failed: ${e.message}")
            }
        }
        networkCallback = null
        vpnProbeCallback = null
        connectivityManager = null
        // A handle to a network that no longer exists must not outlive the tunnel it
        // belonged to: binding the next probe to it would fail, and a failed bind reads
        // as "cannot probe", which is exactly the answer that never restarts anything.
        tunnelNetwork = null
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
        releaseTunnelWakeLock()
        val unexpected = !stopRequested && hevStarted
        stopTunnel(blocking = false)
        if (current === this) current = null
        if (unexpected) {
            SessionController.getOrNull()?.onVpnFailed("VPN service $SERVICE_KILLED_BY_OS")
        }
        super.onDestroy()
    }

    companion object {
        private const val TAG = "AetherVpn"

        private const val NOTIF_BLOCKED =
            "Always-on VPN is active. Connections are blocked until you tap Connect."
        private const val CHANNEL = "aether_vpn"
        private const val NOTIF_ID = 43
        @Volatile
        private var nativeLoaded = false
        private val worker = Executors.newSingleThreadScheduledExecutor { r ->
            Thread(r, "aether-vpn-worker").apply { isDaemon = true }
        }
        private val probeExecutor = Executors.newSingleThreadScheduledExecutor { r ->
            Thread(r, "aether-vpn-probe").apply { isDaemon = true }
        }
        private val mainHandler = Handler(Looper.getMainLooper())
        const val EXTRA_SOCKS_PORT = "socks_port"
        const val ACTION_STOP = "app.aethernext.VPN_STOP"
        const val ACTION_DISCONNECT = "app.aethernext.VPN_DISCONNECT"

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

// ─── item 6: the supervised restart, as a decision and an executable body ──────

/**
 * The one capability test that says "this network is a VPN", kept as a pure
 * function so a JVM test can assert it without a device.
 *
 * There is no public `NET_CAPABILITY_VPN`; the number 33 is
 * [NetworkCapabilities.NET_CAPABILITY_MMTEL]. The platform marks a VPN network
 * with [NetworkCapabilities.TRANSPORT_VPN] and clears
 * [NetworkCapabilities.NET_CAPABILITY_NOT_VPN] on it, so both reads are required:
 * the transport identifies a VPN, and a network still marked NOT_VPN is not one.
 */
internal fun classifiesAsVpn(
    hasTransport: (Int) -> Boolean,
    hasCapability: (Int) -> Boolean,
): Boolean =
    hasTransport(NetworkCapabilities.TRANSPORT_VPN) &&
        !hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)

/** What the scheduled restart callback is going to do when it fires. */
internal sealed interface RestartAction {
    /** The user stopped this session, or a newer start superseded it: touch nothing. */
    data object Cancelled : RestartAction

    /** The dead tunnel is still holding a descriptor: close it, *then* rebuild. */
    data object ReplaceTunnel : RestartAction

    /** Nothing is open: establish straight away. */
    data object EstablishFresh : RestartAction
}

/**
 * The guard a scheduled restart applies when it fires.
 *
 * This is the line that made every dead-tunnel restart a no-op. The old body read
 * `if (stopRequested || tun != null) return`: a tunnel the watchdog had just
 * classified DEAD is by definition still *open* — its descriptor never went away, that
 * is what "blackholing" means — so the only case worth restarting was the one case
 * that bailed out, and the replacement was never established. A dead verdict now
 * means "close it, then rebuild under the current session generation"; only a stop
 * the user asked for, or a generation that has moved on underneath the callback, may
 * cancel it.
 *
 * [armedGen] is the generation the tunnel had when the restart was scheduled, up to
 * 30 s earlier. [currentGen] moving on its own means a teardown or a fresh start
 * happened in between, and reviving the old session from a stale callback is the
 * failure this token exists to stop.
 */
internal fun restartAction(
    tunnelOpen: Boolean,
    stopRequested: Boolean,
    armedGen: Long,
    currentGen: Long,
): RestartAction = when {
    stopRequested -> RestartAction.Cancelled
    armedGen != currentGen -> RestartAction.Cancelled
    tunnelOpen -> RestartAction.ReplaceTunnel
    else -> RestartAction.EstablishFresh
}

/** The steps a supervised restart needs from [AetherVpnService], as a seam. */
internal interface TunnelRestartOps {
    /** Whether a tun descriptor is open — true for the dead-but-still-open tunnel. */
    fun tunnelOpen(): Boolean

    /** Whether the user asked this service to stop. */
    fun stopRequested(): Boolean

    /** The service's current session generation. */
    fun generation(): Long

    /** Tear the current tunnel down, releasing the dead descriptor. */
    fun closeTunnel()

    /** Open the replacement for [port]'s traffic, owned by session generation [gen]. */
    fun establish(port: Int, gen: Long): Boolean

    /** Tell the session its tunnel is back. */
    fun reportEstablished(gen: Long)

    /** Tell the session the restart did not produce a tunnel. */
    fun reportFailed(gen: Long, reason: String)
}

/** How a supervised restart ended, for logs and for tests. */
internal enum class RestartOutcome {
    Cancelled,
    CancelledWhileClosing,
    Replaced,
    EstablishedFresh,
    Failed,
}

/**
 * Carry out one supervised restart.
 *
 * Returns the outcome rather than acting on Android types, so the whole sequence —
 * including the case the bug lived in — is assertable on a JVM: a dead tunnel whose
 * descriptor is still open must be closed and replaced, and a session the user stopped
 * in the meantime must not be revived.
 */
internal fun runSupervisedRestart(
    armedGen: Long,
    port: Int,
    ops: TunnelRestartOps,
): RestartOutcome {
    when (restartAction(ops.tunnelOpen(), ops.stopRequested(), armedGen, ops.generation())) {
        RestartAction.Cancelled -> return RestartOutcome.Cancelled

        RestartAction.EstablishFresh ->
            return establishReplacement(ops, port, ops.generation(), RestartOutcome.EstablishedFresh)

        RestartAction.ReplaceTunnel -> {
            // The order is the fix: a second tunnel opened over a dead one leaves the
            // device routed into the corpse, so the descriptor goes first. Closing it
            // advances the generation by design, which is why the re-check below is
            // against the *user's* stop and not against the token our own close
            // invalidated — the replacement then takes the generation that is current
            // once the dead tunnel is gone.
            ops.closeTunnel()
            if (ops.stopRequested()) return RestartOutcome.CancelledWhileClosing
            return establishReplacement(ops, port, ops.generation(), RestartOutcome.Replaced)
        }
    }
}

private fun establishReplacement(
    ops: TunnelRestartOps,
    port: Int,
    gen: Long,
    succeeded: RestartOutcome,
): RestartOutcome = try {
    if (ops.establish(port, gen)) {
        ops.reportEstablished(gen)
        succeeded
    } else {
        ops.closeTunnel()
        ops.reportFailed(gen, RECONNECT_REQUIRED)
        RestartOutcome.Failed
    }
} catch (t: Throwable) {
    try {
        ops.closeTunnel()
    } catch (_: Exception) {
    }
    ops.reportFailed(gen, t.message ?: RECONNECT_REQUIRED)
    RestartOutcome.Failed
}

// ─── item 7: the data-path probe, as a verdict over a bounded connect ──────────

/**
 * Two independent HTTPS endpoints, addressed numerically so a DNS lookup cannot
 * turn a bounded TCP check into an unbounded resolver wait. A remote provider's
 * own outage must not be sufficient to condemn the tunnel.
 */
internal const val PROBE_HOST = "1.1.1.1"
internal const val PROBE_PORT = 443
internal const val PROBE_SECONDARY_HOST = "8.8.8.8"
internal const val PROBE_SECONDARY_PORT = 443

internal val PROBE_TARGETS = listOf(
    InetSocketAddress(PROBE_HOST, PROBE_PORT),
    InetSocketAddress(PROBE_SECONDARY_HOST, PROBE_SECONDARY_PORT),
)

/** A tunnel is blackholed only when both independent routes give that evidence. */
internal fun probeIndependentTargets(probeOne: (InetSocketAddress) -> PathProbe): PathProbe {
    var inconclusive = false
    for (target in PROBE_TARGETS) {
        when (probeOne(target)) {
            PathProbe.Replied -> return PathProbe.Replied
            PathProbe.Unavailable -> inconclusive = true
            PathProbe.Blackhole -> Unit
        }
    }
    return if (inconclusive) PathProbe.Unavailable else PathProbe.Blackhole
}

/**
 * Maximum time for one connect. Even when both targets time out in sequence,
 * the combined budget must remain below [WINDOW_MS], so the watchdog cannot
 * delay its next poll or a teardown queued behind it.
 */
internal const val PROBE_TIMEOUT_MS = 1_500

/**
 * Whether this poll has to ask the tunnel itself.
 *
 * [SILENT_WINDOWS] counts the window that is closing now, so the first probe is armed
 * one window before a verdict could be reached, and every quieter window costs nothing.
 * After that it repeats once per [SILENT_WINDOWS] rather than once per poll: a phone
 * that is genuinely idle would otherwise pay a fresh handshake through the tunnel every
 * five seconds for as long as it stayed idle, and the failure this measures — a path
 * that stops carrying traffic — is caught within one silent streak either way.
 */
internal fun shouldProbeDataPath(silentWindows: Int): Boolean {
    val closing = silentWindows + 1
    return closing >= SILENT_WINDOWS && closing % SILENT_WINDOWS == 0
}

/** What one bounded connect through the tunnel's own network came back with. */
internal enum class PathProbe {
    /** The connect completed through the TUN: the path carries traffic, silence is idleness. */
    Replied,

    /** The socket was bound to the tunnel and nothing answered within the budget. */
    Blackhole,

    /** No probe was attempted — the platform gave no tunnel network to bind to. */
    Unavailable,
}

/** The three answers a fully-silent window can mean, kept apart on purpose. */
internal enum class SilentPathVerdict {
    /** Traffic got through when asked; the device simply has nothing to send. */
    AliveIdle,

    /** The underlying network is up and the tunnel answers nothing: unhealthy. */
    DeadBlackhole,

    /** Not the tunnel's fault, or not measurable: the network is gone, or cannot be probed. */
    NotProvable,
}

/**
 * Decide what silence means.
 *
 * The probe used to be "does Wi-Fi advertise internet", which is a question about the
 * radio: a tunnel that swallows every packet rides a network that answers it perfectly,
 * so six silent windows closed as `probeFailed = false` → `Alive`, and a blackhole kept
 * its green badge forever. Availability is now an *input*, not the verdict, and it only
 * ever excuses silence when there is genuinely no network to carry traffic.
 *
 * "Genuinely idle" ([SilentPathVerdict.AliveIdle]) and "probe failed"
 * ([SilentPathVerdict.DeadBlackhole]) stay separate answers: the first must never cost
 * a restart, the second must.
 */
internal fun verdictForSilentPath(underlyingAvailable: Boolean, probe: PathProbe): SilentPathVerdict = when {
    probe == PathProbe.Blackhole && underlyingAvailable -> SilentPathVerdict.DeadBlackhole
    probe == PathProbe.Replied && underlyingAvailable -> SilentPathVerdict.AliveIdle
    else -> SilentPathVerdict.NotProvable
}

/**
 * One bounded, size-bounded connect attempt, bound to the tunnel by [bindToTunnel].
 *
 * Nothing is read and no payload is sent — a TCP handshake is the whole cost — and the
 * socket is closed on every path. A binder that refuses (no tunnel network, an API level
 * that will not hand one out) yields [PathProbe.Unavailable] *before* any connect,
 * because an unbound socket from this process goes straight past the TUN: it would
 * return [PathProbe.Replied] about a tunnel that is carrying nothing.
 */
internal fun probeThroughTunnel(
    bindToTunnel: (Socket) -> Boolean,
    target: InetSocketAddress,
    timeoutMs: Int,
    newSocket: () -> Socket = { Socket() },
    note: (String) -> Unit = {},
): PathProbe {
    val socket = newSocket()
    try {
        val bound = try {
            bindToTunnel(socket)
        } catch (e: Exception) {
            // A bind that refuses — `Network.bindSocket` throws, and a `SecurityException`
            // is a real answer — is "not measured", never "the tunnel is dead".
            note("probe could not be bound: ${e.message}")
            false
        }
        if (!bound) {
            note("probe skipped: the socket could not be bound to the tunnel")
            return PathProbe.Unavailable
        }
        return try {
            socket.connect(target, timeoutMs)
            PathProbe.Replied
        } catch (e: SocketTimeoutException) {
            note("probe through the tunnel timed out: ${e.message}")
            PathProbe.Blackhole
        } catch (e: NoRouteToHostException) {
            note("probe has no route through the tunnel: ${e.message}")
            PathProbe.Blackhole
        } catch (e: IOException) {
            // A refused connection can be a response from the far end, and a
            // local socket error is not evidence that the VPN blackholed data.
            note("probe through the tunnel was inconclusive: ${e.message}")
            PathProbe.Unavailable
        }
    } finally {
        try {
            socket.close()
        } catch (_: IOException) {
        }
    }
}

// ─── item 18: what happens when the OS kills these services ───────────────────

/** The sentence the app shows when the system took the tunnel away. */
internal const val SERVICE_KILLED_BY_OS =
    "was stopped by the system while it was carrying this device's traffic. " +
        "Aether does not reconnect on its own — tap Connect to resume."

/** The service the restart policy is answering for. */
internal enum class ServiceRole { VpnTunnel, EngineKeeper }

/** What a service tells Android about recreating it. */
internal enum class StartAction {
    /** Do not come back: whatever this service existed for is gone with it. */
    RemainStopped,

    /** Re-deliver the original start intent after a kill, so a live session resumes. */
    Redeliver,

    /** Live only while the app keeps it started; the system must never re-create it. */
    KeepAliveOnly,
}

/**
 * The one restart rule both services answer to (T217, item 18).
 *
 * Option (b) of the audit's two — manual reconnection, stated in the product surface —
 * is what is implemented, and the rule below is why it is the only coherent answer for
 * *this* design rather than a deferral: [AetherVpnService] is tun2socks, forwarding into
 * a SOCKS listener owned by the engine child process. A kill takes the child, the
 * controller and the WebView with it, so a `START_STICKY` tunnel that came back could
 * only carry the device into a port nothing is bound to — the exact "interface up, no
 * data path, green badge" failure the liveness watchdog exists to detect. Option (a) is
 * kept representable rather than deleted: [StartAction.Redeliver] is reachable when the
 * session really is still there to resume, and [startCommandFor] is the only place that
 * maps an answer onto an Android constant.
 *
 * What the user can instead rely on is already in the tree and is what this rule points
 * at: [SessionLedger] reports an unexpected end on the next launch, and
 * `launchAtLogin` — the explicit resume switch — drives [BootReceiver]'s tap-to-start
 * handoff, which never connects unattended.
 */
internal object ServiceRestartPolicy {
    fun decide(
        role: ServiceRole,
        redelivered: Boolean,
        userAskedToStop: Boolean,
        // The three resume preconditions are only ever consulted on a redelivered
        // start, and reading them is I/O (a binder call and a preferences load). A
        // caller that cannot reach the branch leaves them at their `false` answers
        // rather than paying for them on the thread that has to return.
        tunnelHasLivePath: Boolean = false,
        consentValid: Boolean = false,
        savedStateValid: Boolean = false,
    ): StartAction = when {
        // An explicit stop is the end of the service's life in every reading.
        userAskedToStop -> StartAction.RemainStopped

        // The keeper only holds a process open for a session that is already gone.
        role == ServiceRole.EngineKeeper -> StartAction.RemainStopped

        // The supported "restart path": a redelivered start, a session that still has
        // an engine to carry the traffic, a VPN permission that was not withdrawn, and
        // saved state that describes a tunnel rather than a corrupt blob read back as
        // defaults. All four, or nothing: any one missing re-establishes routing nobody
        // can see running.
        redelivered && tunnelHasLivePath && consentValid && savedStateValid -> StartAction.Redeliver

        redelivered -> StartAction.RemainStopped

        else -> StartAction.KeepAliveOnly
    }

    /** The Android constant for [action]. The only place a start flag is spelled. */
    fun startCommandFor(action: StartAction): Int = when (action) {
        StartAction.RemainStopped -> Service.START_NOT_STICKY
        StartAction.KeepAliveOnly -> Service.START_NOT_STICKY
        StartAction.Redeliver -> Service.START_REDELIVER_INTENT
    }
}
