package app.aethernext

import android.content.Context
import android.util.Log
import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

enum class SupervisorState {
    IDLE,
    SCANNING,
    CONNECTING,
    CONNECTED,
    STOPPING,
}

interface ProcessLauncher {
    fun launch(command: List<String>, env: Map<String, String>): Process
}

class DefaultProcessLauncher(private val workingDir: File? = null) : ProcessLauncher {
    override fun launch(command: List<String>, env: Map<String, String>): Process {
        val pb = ProcessBuilder(command)
        workingDir?.let { pb.directory(it) }
        pb.redirectErrorStream(true)
        pb.environment().putAll(env)
        return pb.start()
    }
}

/**
 * Spawns the packaged engine binary.
 *
 * On modern Android (W^X), executables under filesDir are not runnable (EACCES/13).
 * Prefer [nativeLibraryDir]/libaether.so which is already executable.
 */
open class EngineRunner(
    private val context: Context,
    private val onLine: (String) -> Unit,
    private val onExit: (Int?, Boolean) -> Unit,
    private val launcher: ProcessLauncher = DefaultProcessLauncher(context.filesDir),
) {
    private val processRef = AtomicReference<Process?>(null)
    private val running = AtomicBoolean(false)
    private val supervisorState = AtomicReference(SupervisorState.IDLE)
    private val generation = java.util.concurrent.atomic.AtomicLong(0)
    private val lifecycleLock = Any()
    // True when the current process was launched as a scan, so stop() sends the
    // cooperative "cancel" (persist best-so-far) rather than "shutdown".
    private val scanMode = AtomicBoolean(false)

    fun isRunning(): Boolean = running.get()

    fun isScanMode(): Boolean = scanMode.get()

    fun getState(): SupervisorState = supervisorState.get()

    fun getGeneration(): Long = generation.get()

    fun setConnected() {
        if (supervisorState.get() == SupervisorState.CONNECTING) {
            supervisorState.set(SupervisorState.CONNECTED)
        }
    }

    fun pid(): Int? {
        val p = processRef.get() ?: return null
        return try {
            val m = p.javaClass.getMethod("pid")
            (m.invoke(p) as? Number)?.toInt()
        } catch (_: Exception) {
            null
        }
    }

    open fun buildProcessCommand(binary: File): List<String> {
        return listOf(binary.absolutePath)
    }

    open fun configureProcessEnvironment(settings: Settings, binary: File): Map<String, String> {
        val configDir = File(context.filesDir, "config").apply { mkdirs() }
        return engineEnv(
            settings = settings,
            configPath = File(configDir, "aether.toml").absolutePath,
            homeDir = context.filesDir.absolutePath,
            tmpDir = context.cacheDir.absolutePath,
        )
    }

    /**
     * The engine's environment, as a pure function.
     *
     * It used to be reachable only through an overridable method that needed a
     * `Context`, which is how the test suite ended up asserting a stub of it instead
     * of the values the child actually receives (T2xx).
     */
    internal fun engineEnv(
        settings: Settings,
        configPath: String,
        homeDir: String,
        tmpDir: String,
    ): Map<String, String> {
        val protocolEnv = protocolEnv(settings.protocol, settings.transport)

        val env = mutableMapOf<String, String>(
            "AETHER_PROTOCOL" to protocolEnv,
            "AETHER_SCAN" to settings.scanMode,
            "AETHER_IP" to settings.ipVersion,
            "AETHER_NOIZE" to noizeEnv(settings.noize),
            "AETHER_SOCKS" to "127.0.0.1:${settings.socksPort}",
            "AETHER_HTTP" to "127.0.0.1:${settings.httpPort}",
            "AETHER_CONFIG" to configPath,
            // The key is handed over on the child's stdin (see
            // handoffConfigKey); a process environment lives as long as the
            // process and is readable by anything that can open it.
            "AETHER_CONFIG_KEY_STDIN" to "1",
            "AETHER_MASQUE_HTTP2" to (if (isHttp2(settings.protocol, settings.transport)) "1" else "0"),
            "AETHER_QUIC_INITIAL_FRAG" to quicFragEnv(settings),
            "AETHER_TUN" to "0",
            "AETHER_WG_NO_PROFILE_RETRY" to "1",
            "AETHER_CONTROL_STDIN" to "1",
            "RUST_LOG" to "info",
            "HOME" to homeDir,
            "TMPDIR" to tmpDir
        )
        if (settings.peer.isNotBlank()) {
            env["AETHER_PEER"] = settings.peer.trim()
        }
        if (settings.noize.equals("custom", ignoreCase = true)) {
            env["AETHER_NOIZE_JC"] = settings.noizeJc.toString()
            env["AETHER_NOIZE_JMIN"] = settings.noizeJmin.toString()
            env["AETHER_NOIZE_JMAX"] = settings.noizeJmax.toString()
            env["AETHER_NOIZE_INTERVAL_MS"] = settings.noizeIntervalMs.toString()
        }
        return env
    }

    /**
     * Send the envelope key down the control pipe the engine already listens on.
     * Returns false when the write failed; the caller must then tear the child
     * down, because it will otherwise sit waiting for a key until its own
     * handoff deadline expires.
     */
    /**
     * The envelope key. A seam so tests (and nothing else) can supply it without
     * touching AndroidKeyStore, which is unavailable under plain JVM unit tests.
     */
    open fun configKey(): String = ConfigKeyStore.loadOrCreate(context)

    /**
     * Send the envelope key down the control pipe the engine already listens on.
     *
     * @return `null` on success, otherwise the *cause* — not a verdict. The failure
     *   this replaces reported a keystore that never came back, a child that closed
     *   its stdin, and an I/O error as one indistinguishable "could not receive its
     *   configuration key", so a KeyStore that needs re-provisioning looked exactly
     *   like a broken download (T2xx).
     */
    private fun handoffConfigKey(proc: Process): String? = try {
        val key = configKey()
        val stream = proc.outputStream
        stream.write("key ".toByteArray(Charsets.US_ASCII))
        stream.write(key.toByteArray(Charsets.US_ASCII))
        stream.write(byteArrayOf(0x0A)) // line terminator for the control channel
        stream.flush()
        null
    } catch (e: Exception) {
        Log.e(TAG, "config key handoff failed: ${e.message}", e)
        // The cause chain, verbatim: `ConfigKeyStore.loadOrCreate` throws the real
        // reason (keystore unavailable, a KeyStoreException, a failed retry loop) and
        // it used to die in a log line no user ever sees.
        "${e.javaClass.simpleName}: ${e.message ?: e.toString()}"
    }

    /**
     * A daemon reader thread for one child's stdout.
     *
     * Raw non-daemon `Thread().start()` per child meant a wedged pipe held the JVM
     * open after the service was torn down, and nothing bounded how many such threads
     * a flapping engine could leave behind.
     */
    private fun startIoThread(name: String, body: () -> Unit) {
        Thread(body, name).apply { isDaemon = true }.start()
    }

    /**
     * Release the child's pipes. The control stream is deliberately left open while
     * the child runs — it is how `shutdown`/`cancel` reach it — so the only moment it
     * is safe to close it is once the process is gone.
     */
    internal fun closeChildStreams(proc: Process?) {
        proc ?: return
        listOf(proc.outputStream, proc.errorStream, proc.inputStream).forEach { stream ->
            try {
                stream.close()
            } catch (_: Exception) {
            }
        }
    }

    fun start(settings: Settings): String? = synchronized(lifecycleLock) {
        if (running.get() || supervisorState.get() != SupervisorState.IDLE) {
            return "Aether is already running"
        }
        val binary = resolveEngine()
            ?: return "Engine binary not found in the APK (libaether.so / assets)."
        scanMode.set(false)
        running.set(true)
        supervisorState.set(SupervisorState.CONNECTING)
        val currentGeneration = generation.incrementAndGet()
        return try {
            Log.i(TAG, "starting engine: ${binary.absolutePath} exists=${binary.exists()} canExec=${binary.canExecute()} len=${binary.length()}")

            val command = buildProcessCommand(binary)
            val env = configureProcessEnvironment(settings, binary)

            val proc = try {
                launcher.launch(command, env)
            } catch (e: Exception) {
                Log.e(TAG, "Process launch failed for ${binary.absolutePath}: ${e.message}", e)
                throw e
            }

            processRef.set(proc)
            val handoffFailure = handoffConfigKey(proc)
            if (handoffFailure != null) {
                proc.destroy()
                proc.destroyForcibly()
                closeChildStreams(proc)
                running.set(false)
                supervisorState.set(SupervisorState.IDLE)
                processRef.set(null)
                return "Engine started but could not receive its configuration key — $handoffFailure"
            }
            startIoThread("aether-engine-io") {
                try {
                    BufferedReader(InputStreamReader(proc.inputStream)).use { reader ->
                        var line: String?
                        while (reader.readLine().also { line = it } != null) {
                            onLine(line!!)
                        }
                    }
                } catch (e: Exception) {
                    Log.w(TAG, "reader ended: ${e.message}")
                } finally {
                    val code = try {
                        proc.waitFor()
                    } catch (_: Exception) {
                        null
                    }
                    // The child is gone: its control pipe can be closed now, and not a
                    // moment earlier — it is how `shutdown` reaches a living engine.
                    closeChildStreams(proc)
                    // EOF on stdout is not process death. A child that closes or
                    // redirects stdout used to flip the runner to IDLE while the
                    // engine was still up, and the supervisor then launched a
                    // *second* engine: two tunnels, two route tables, one device.
                    if (proc.isAlive) {
                        Log.w(TAG, "engine stdout closed while process still alive; not marking it stopped")
                    } else if (generation.compareAndSet(currentGeneration, currentGeneration + 1)) {
                        running.set(false)
                        supervisorState.set(SupervisorState.IDLE)
                        processRef.compareAndSet(proc, null)
                        onExit(code, false)
                    }
                }
            }
            null
        } catch (e: Exception) {
            running.set(false)
            supervisorState.set(SupervisorState.IDLE)
            processRef.set(null)
            Log.e(TAG, "start failed", e)
            "Could not start engine: ${e.message}"
        }
    }

    open fun configureScanEnvironment(
        protocol: String,
        ipVersion: String,
        concurrency: Int,
        timeoutMs: Int,
        noize: String,
    ): Map<String, String> {
        val configDir = File(context.filesDir, "config").apply { mkdirs() }
        val settings = SettingsStore(context).load()
        return scanEnv(
            protocol = protocol,
            ipVersion = ipVersion,
            concurrency = concurrency,
            timeoutMs = timeoutMs,
            noize = noize,
            settings = settings,
            configPath = File(configDir, "aether.toml").absolutePath,
            homeDir = context.filesDir.absolutePath,
            tmpDir = context.cacheDir.absolutePath,
        )
    }

    /**
     * The scan child's environment, as a pure function (see [engineEnv]).
     *
     * Two mappings used to be wrong here and both were invisible: the protocol line
     * knew only the long name, so a user who had chosen `wg` — a value this app
     * validates and stores — got a MASQUE probe set instead, and `AETHER_SCAN` was
     * hardcoded to `balanced`, so the scan mode the user picked in Settings was thrown
     * away the moment they pressed Scan.
     */
    internal fun scanEnv(
        protocol: String,
        ipVersion: String,
        concurrency: Int,
        timeoutMs: Int,
        noize: String,
        settings: Settings,
        configPath: String,
        homeDir: String,
        tmpDir: String,
    ): Map<String, String> = mutableMapOf<String, String>(
        "AETHER_PROTOCOL" to protocolEnv(protocol, settings.transport),
        "AETHER_SCAN_ONLY" to "1",
        "AETHER_SCAN_EXHAUSTIVE" to "1",
        "AETHER_SCAN" to ScanLimits.scanProfile(settings.scanMode),
        "AETHER_IP" to ipVersion,
        "AETHER_NOIZE" to noizeEnv(noize),
        "AETHER_SCAN_CONCURRENCY" to concurrency.toString(),
        "AETHER_SCAN_TIMEOUT_MS" to timeoutMs.toString(),
        "AETHER_CONFIG" to configPath,
        // The key is handed over on the child's stdin (see
        // handoffConfigKey); a process environment lives as long as the
        // process and is readable by anything that can open it.
        "AETHER_CONFIG_KEY_STDIN" to "1",
        "AETHER_MASQUE_HTTP2" to (if (isHttp2(protocol, settings.transport)) "1" else "0"),
        "AETHER_QUIC_INITIAL_FRAG" to quicFragEnv(settings),
        "AETHER_TUN" to "0",
        "AETHER_WG_NO_PROFILE_RETRY" to "1",
        "AETHER_CONTROL_STDIN" to "1",
        "RUST_LOG" to "info",
        "HOME" to homeDir,
        "TMPDIR" to tmpDir,
    )

    /**
     * Start the engine in scan-only mode (no tunnel, no VPN).
     * The engine emits AETHER_EVENT lines for scan progress/hits.
     */
    fun startScan(
        protocol: String,
        ipVersion: String,
        concurrency: Int,
        timeoutMs: Int,
        noize: String,
    ): String? = synchronized(lifecycleLock) {
        if (running.get() || supervisorState.get() != SupervisorState.IDLE) {
            return "Aether is already running"
        }
        val binary = resolveEngine()
            ?: return "Engine binary not found in the APK (libaether.so / assets)."
        scanMode.set(true)
        running.set(true)
        supervisorState.set(SupervisorState.SCANNING)
        val currentGeneration = generation.incrementAndGet()
        return try {
            val command = buildProcessCommand(binary)
            val env = configureScanEnvironment(protocol, ipVersion, concurrency, timeoutMs, noize)

            val proc = launcher.launch(command, env)
            processRef.set(proc)
            val handoffFailure = handoffConfigKey(proc)
            if (handoffFailure != null) {
                proc.destroy()
                proc.destroyForcibly()
                closeChildStreams(proc)
                running.set(false)
                supervisorState.set(SupervisorState.IDLE)
                processRef.set(null)
                return "Engine started but could not receive its configuration key — $handoffFailure"
            }
            startIoThread("aether-scan-io") {
                try {
                    BufferedReader(InputStreamReader(proc.inputStream)).use { reader ->
                        var line: String?
                        while (reader.readLine().also { line = it } != null) {
                            onLine(line!!)
                        }
                    }
                } catch (e: Exception) {
                    Log.w(TAG, "scan reader ended: ${e.message}")
                } finally {
                    val code = try { proc.waitFor() } catch (_: Exception) { null }
                    closeChildStreams(proc)
                    // EOF on stdout is not process death. A child that closes or
                    // redirects stdout used to flip the runner to IDLE while the
                    // engine was still up, and the supervisor then launched a
                    // *second* engine: two tunnels, two route tables, one device.
                    if (proc.isAlive) {
                        Log.w(TAG, "engine stdout closed while process still alive; not marking it stopped")
                    } else if (generation.compareAndSet(currentGeneration, currentGeneration + 1)) {
                        running.set(false)
                        supervisorState.set(SupervisorState.IDLE)
                        processRef.compareAndSet(proc, null)
                        onExit(code, true)
                    }
                }
            }
            null
        } catch (e: Exception) {
            running.set(false)
            supervisorState.set(SupervisorState.IDLE)
            processRef.set(null)
            "Could not start scan: ${e.message}"
        }
    }

    fun stopAndWait(timeoutMs: Long = 5000): Boolean = synchronized(lifecycleLock) {
        generation.incrementAndGet()
        val p = processRef.get() ?: run {
            running.set(false)
            supervisorState.set(SupervisorState.IDLE)
            return true
        }
        supervisorState.set(SupervisorState.STOPPING)
        try {
            val cmd = if (scanMode.get()) "cancel\n" else "shutdown\n"
            p.outputStream.write(cmd.toByteArray())
            p.outputStream.flush()
        } catch (_: Exception) {
        }
        val graceful = System.currentTimeMillis() + (timeoutMs * 3 / 5).coerceAtLeast(1000)
        val deadline = System.currentTimeMillis() + timeoutMs
        while (p.isAlive && System.currentTimeMillis() < graceful) {
            Thread.sleep(50)
        }
        if (p.isAlive) {
            p.destroy()
            while (p.isAlive && System.currentTimeMillis() < deadline) {
                Thread.sleep(50)
            }
            if (p.isAlive) {
                p.destroyForcibly()
                val hard = System.currentTimeMillis() + 1000
                while (p.isAlive && System.currentTimeMillis() < hard) {
                    Thread.sleep(20)
                }
            }
        }
        if (p.isAlive) {
            Log.e(TAG, "Process failed to stop after forced kill escalation; retaining STOPPING state")
            running.set(true)
            supervisorState.set(SupervisorState.STOPPING)
            false
        } else {
            running.set(false)
            supervisorState.set(SupervisorState.IDLE)
            processRef.compareAndSet(p, null)
            // The child is gone, so the control pipe no longer has a reader.
            closeChildStreams(p)
            true
        }
    }

    fun stop() {
        stopAndWait(5000)
    }

    protected open fun resolveEngine(): File? {
        // The only engine this will run is the one signed inside the APK. There is
        // deliberately no "custom path" input: on API 29+ the payload can only be
        // executed from `nativeLibraryDir`, and a path supplied from the WebView —
        // the settings JSON — is exactly the input that must never reach
        // `ProcessBuilder`.
        //
        // 1) APK native lib dir — the only place Android allows executing our payload
        // on API 29+. This is a hard dependency on the manifest packing the native
        // libraries *extracted* (`extractNativeLibs="true"`, matched by
        // `packaging.jniLibs.useLegacyPackaging = true`): with the modern in-APL
        // packaging the loader `dlopen`s `libaether.so` straight out of the archive and
        // no path under `nativeLibraryDir` exists on disk, so every engine start here
        // would fail with "binary not found". The two settings must move together.
        val libDir = File(context.applicationInfo.nativeLibraryDir)
        listOf("libaether.so", "aether").forEach { name ->
            val f = File(libDir, name)
            if (f.exists()) {
                Log.i(TAG, "engine from nativeLibraryDir: ${f.absolutePath}")
                return f
            }
        }
        Log.w(TAG, "nativeLibraryDir has no engine: $libDir contents=${libDir.list()?.joinToString()}")

        // Refuse extracted executables; only APK-signed native libraries are trusted.

        return null
    }

    companion object {
        private const val TAG = "EngineRunner"

        /** The engine's protocol token. `wg` and `wireguard` are the same choice. */
        /**
         * The transport token handed to the engine, or a refusal.
         *
         * The same rule as [noizeEnv] below: translating two names for one feature
         * is fine, guessing is not. The `else -> "masque"` this replaces answered a
         * request for WARP-in-WARP with a MASQUE tunnel and nothing written down,
         * and the engine now refuses a name it does not know rather than choosing
         * for the user — so a guess here would surface as a failed start.
         */
        internal fun protocolEnv(protocol: String, transport: String): String =
            when (protocol.lowercase().trim()) {
                "wireguard", "wg" -> "wg"
                "masque", "masque-h2", "masque-h3", "h2", "h3" -> "masque"
                "gool", "wiw", "warp-in-warp", "warpinwarp" -> "gool"
                // Legacy value a shipped config can still hold; the engine resolves
                // it to MASQUE and says so, so it is passed through, not rewritten.
                "warp" -> "warp"
                else -> throw IllegalArgumentException(
                    "protocol '$protocol' has no engine equivalent; the engine understands " +
                        "masque|masque-h2|masque-h3|wg|wireguard|gool|warp-in-warp|warp. " +
                        "Re-select it in Settings.",
                )
            }

        internal fun isHttp2(protocol: String, transport: String): Boolean =
            protocol.lowercase() == "masque-h2" || transport.lowercase() == "h2"

        internal fun quicFragEnv(settings: Settings): String =
            if (settings.quicInitialFrag) settings.quicInitialFragSize.coerceIn(16, 512).toString() else "0"

        /**
         * The noise token handed to the engine, or a refusal.
         *
         * Translating is fine — the app's `high` and the engine's `heavy` are one
         * feature with two names. Guessing is not: an unmappable value used to be sent
         * through verbatim, where the engine's own fallback decided what the user got.
         */
        internal fun noizeEnv(noize: String): String =
            NoizeProfiles.forEngine(noize) ?: throw IllegalArgumentException(
                "noise profile '$noize' has no engine equivalent; the engine understands " +
                    "${NoizeProfiles.engineValues.joinToString("|")}. Re-select it in Settings.",
            )
    }
}
