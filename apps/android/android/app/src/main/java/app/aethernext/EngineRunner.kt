package app.aethernext

import android.content.Context
import android.util.Log
import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

/**
 * Spawns the packaged engine binary.
 *
 * On modern Android (W^X), executables under filesDir are not runnable (EACCES/13).
 * Prefer [nativeLibraryDir]/libaether.so which is already executable.
 */
class EngineRunner(
    private val context: Context,
    private val onLine: (String) -> Unit,
    private val onExit: (Int?) -> Unit,
) {
    private val processRef = AtomicReference<Process?>(null)
    private val running = AtomicBoolean(false)
    private val generation = java.util.concurrent.atomic.AtomicLong(0)
    // True when the current process was launched as a scan, so stop() sends the
    // cooperative "cancel" (persist best-so-far) rather than "shutdown".
    private val scanMode = AtomicBoolean(false)

    fun isRunning(): Boolean = running.get()

    fun pid(): Int? {
        val p = processRef.get() ?: return null
        return try {
            val m = p.javaClass.getMethod("pid")
            (m.invoke(p) as? Int)
        } catch (_: Exception) {
            null
        }
    }

    fun start(settings: Settings): String? {
        val binary = resolveEngine(settings.enginePath)
            ?: return "Engine binary not found in the APK (libaether.so / assets)."
        scanMode.set(false)
        if (!running.compareAndSet(false, true)) {
            return "Aether is already running"
        }
        val currentGeneration = generation.incrementAndGet()
        return try {
            Log.i(TAG, "starting engine: ${binary.absolutePath} exists=${binary.exists()} canExec=${binary.canExecute()} len=${binary.length()}")

            val configDir = File(context.filesDir, "config").apply { mkdirs() }
            val configPath = File(configDir, "aether.toml").absolutePath
            val homeDir = context.filesDir.absolutePath

            // Map UI protocol names to engine env values.
            val protocolEnv = when (settings.protocol.lowercase()) {
                "wireguard", "wg" -> "wg"
                "gool", "wiw", "warp-in-warp" -> "gool"
                else -> "masque"
            }

            val pb = ProcessBuilder(binary.absolutePath).apply {
                // Work from a writable app dir (config/logs), not the lib folder.
                directory(context.filesDir)
                redirectErrorStream(true)
                environment().apply {
                    put("AETHER_PROTOCOL", protocolEnv)
                    // Forced endpoint from Scanner "Connect Direct"; empty = auto-scan.
                    if (settings.peer.isNotBlank()) put("AETHER_PEER", settings.peer)
                    put("AETHER_SCAN", settings.scanMode)
                    put("AETHER_IP", settings.ipVersion)
                    put("AETHER_NOIZE", settings.noize)
                    put("AETHER_SOCKS", "127.0.0.1:${settings.socksPort}")
                    put("AETHER_HTTP", "127.0.0.1:${settings.httpPort}")
                    put("AETHER_CONFIG", configPath)
                    put("AETHER_CONFIG_KEY", ConfigKeyStore.loadOrCreate(context))
                    put("AETHER_MASQUE_HTTP2", if (settings.transport == "h2") "1" else "0")
                    // H3 anti-DPI: split the QUIC Initial ClientHello across two
                    // datagrams (only meaningful on SNI-filtering networks).
                    put(
                        "AETHER_QUIC_INITIAL_FRAG",
                        if (settings.quicInitialFrag) settings.quicInitialFragSize.coerceIn(16, 512).toString() else "0",
                    )
                    // Android full-device routing uses hev tun2socks + VpnService, not engine TUN.
                    put("AETHER_TUN", "0")
                    put("AETHER_WG_NO_PROFILE_RETRY", "1")
                    // Control channel so stop() can shut the session down gracefully.
                    put("AETHER_CONTROL_STDIN", "1")
                    put("RUST_LOG", "info")
                    put("HOME", homeDir)
                    put("TMPDIR", context.cacheDir.absolutePath)
                    if (settings.noize.equals("custom", ignoreCase = true)) {
                        put("AETHER_NOIZE_JC", settings.noizeJc.toString())
                        put("AETHER_NOIZE_JMIN", settings.noizeJmin.toString())
                        put("AETHER_NOIZE_JMAX", settings.noizeJmax.toString())
                        put("AETHER_NOIZE_INTERVAL_MS", settings.noizeIntervalMs.toString())
                    }
                }
            }

            val proc = try {
                pb.start()
            } catch (e: Exception) {
                Log.e(TAG, "ProcessBuilder failed for ${binary.absolutePath}: ${e.message}", e)
                // No sh -c fallback: data dirs are noexec on modern Android and hide real errors.
                throw e
            }

            processRef.set(proc)
            Thread({
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
                    if (generation.compareAndSet(currentGeneration, currentGeneration + 1)) {
                        running.set(false)
                        processRef.compareAndSet(proc, null)
                        onExit(code)
                    }
                }
            }, "aether-engine-io").start()
            null
        } catch (e: Exception) {
            running.set(false)
            processRef.set(null)
            Log.e(TAG, "start failed", e)
            "Could not start engine: ${e.message}"
        }
    }

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
    ): String? {
        val binary = resolveEngine("")
            ?: return "Engine binary not found in the APK (libaether.so / assets)."
        scanMode.set(true)
        if (!running.compareAndSet(false, true)) {
            return "Aether is already running"
        }
        val currentGeneration = generation.incrementAndGet()
        return try {
            val configDir = File(context.filesDir, "config").apply { mkdirs() }
            val configPath = File(configDir, "aether.toml").absolutePath
            val homeDir = context.filesDir.absolutePath

            val protocolEnv = if (protocol == "wireguard") "wg" else "masque"
            val isH2 = protocol == "masque-h2"
            val settings = SettingsStore(context).load()

            val pb = ProcessBuilder(binary.absolutePath).apply {
                directory(context.filesDir)
                redirectErrorStream(true)
                environment().apply {
                    put("AETHER_PROTOCOL", protocolEnv)
                    put("AETHER_SCAN_ONLY", "1")
                    put("AETHER_SCAN_EXHAUSTIVE", "1")
                    put("AETHER_SCAN", "balanced")
                    put("AETHER_IP", ipVersion)
                    put("AETHER_NOIZE", noize)
                    put("AETHER_SCAN_CONCURRENCY", concurrency.toString())
                    put("AETHER_SCAN_TIMEOUT_MS", timeoutMs.toString())
                    put("AETHER_CONFIG", configPath)
                    put("AETHER_CONFIG_KEY", ConfigKeyStore.loadOrCreate(context))
                    put("AETHER_MASQUE_HTTP2", if (isH2) "1" else "0")
                    put(
                        "AETHER_QUIC_INITIAL_FRAG",
                        if (settings.quicInitialFrag) settings.quicInitialFragSize.coerceIn(16, 512).toString() else "0",
                    )
                    put("AETHER_TUN", "0")
                    put("AETHER_WG_NO_PROFILE_RETRY", "1")
                    // Control channel so stop() can cancel the scan gracefully.
                    put("AETHER_CONTROL_STDIN", "1")
                    put("RUST_LOG", "info")
                    put("HOME", homeDir)
                    put("TMPDIR", context.cacheDir.absolutePath)
                }
            }

            val proc = pb.start()
            processRef.set(proc)
            Thread({
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
                    if (generation.compareAndSet(currentGeneration, currentGeneration + 1)) {
                        running.set(false)
                        processRef.compareAndSet(proc, null)
                        onExit(code)
                    }
                }
            }, "aether-scan-io").start()
            null
        } catch (e: Exception) {
            running.set(false)
            processRef.set(null)
            "Could not start scan: ${e.message}"
        }
    }

    fun stop() {
        generation.incrementAndGet()
        val p = processRef.getAndSet(null) ?: run {
            running.set(false)
            return
        }
        // Graceful teardown over the engine's control channel instead of an
        // immediate SIGKILL that can interrupt a cache write: a scan gets "cancel"
        // (persist best-so-far), a tunnel gets "shutdown" (end the session).
        try {
            val cmd = if (scanMode.get()) "cancel\n" else "shutdown\n"
            p.outputStream.write(cmd.toByteArray())
            p.outputStream.flush()
        } catch (_: Exception) {
        }
        Thread({
            try {
                // Wait for a clean exit, then escalate: SIGTERM, then SIGKILL.
                val graceful = System.currentTimeMillis() + 3000
                while (p.isAlive && System.currentTimeMillis() < graceful) Thread.sleep(50)
                if (p.isAlive) {
                    p.destroy()
                    val hard = System.currentTimeMillis() + 2000
                    while (p.isAlive && System.currentTimeMillis() < hard) Thread.sleep(50)
                    if (p.isAlive) p.destroyForcibly()
                }
            } catch (_: Exception) {
                try { p.destroyForcibly() } catch (_: Exception) {
                }
            }
        }, "aether-engine-stop").start()
        running.set(false)
    }

    private fun resolveEngine(configured: String): File? {
        // Never run arbitrary user paths (bridge can set enginePath). Only APK natives / staged assets.
        if (configured.isNotBlank()) {
            Log.w(TAG, "ignoring custom enginePath for security: $configured")
        }

        // 1) APK native lib dir — only place Android allows executing our payload on API 29+.
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
    }
}
