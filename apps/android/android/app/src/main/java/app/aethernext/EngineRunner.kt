package app.aethernext

import android.content.Context
import android.os.Build
import android.system.Os
import android.util.Log
import java.io.BufferedReader
import java.io.File
import java.io.FileOutputStream
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
                    put("AETHER_SCAN", settings.scanMode)
                    put("AETHER_IP", settings.ipVersion)
                    put("AETHER_NOIZE", settings.noize)
                    put("AETHER_SOCKS", "127.0.0.1:${settings.socksPort}")
                    put("AETHER_HTTP", "127.0.0.1:${settings.httpPort}")
                    put("AETHER_CONFIG", configPath)
                    put("AETHER_MASQUE_HTTP2", if (settings.transport == "h2") "1" else "0")
                    // Android full-device routing uses hev tun2socks + VpnService, not engine TUN.
                    put("AETHER_TUN", "0")
                    put("AETHER_WG_NO_PROFILE_RETRY", "1")
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

    fun stop() {
        generation.incrementAndGet()
        val p = processRef.getAndSet(null) ?: return
        try {
            p.destroy()
            Thread {
                try {
                    Thread.sleep(1500)
                    if (p.isAlive) p.destroyForcibly()
                } catch (_: Exception) {
                }
            }.start()
        } catch (_: Exception) {
        }
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

        // 2) Already extracted under filesDir (may fail exec on API 29+).
        val extracted = File(context.filesDir, "engine/aether")
        if (extracted.exists() && extracted.length() > 0) {
            ensureExecutable(extracted)
            if (canTryExec(extracted)) return extracted
        }

        // 3) Copy from assets into native-like name under codeCacheDir (sometimes executable).
        val fromAssets = extractAssetEngine()
        if (fromAssets != null) return fromAssets

        return null
    }

    private fun extractAssetEngine(): File? {
        return try {
            // Prefer codeCacheDir; still may be non-exec on some devices.
            val destDir = File(context.codeCacheDir, "engine").apply { mkdirs() }
            val dest = File(destDir, "libaether.so")
            context.assets.open("engine/aether").use { input ->
                FileOutputStream(dest).use { output -> input.copyTo(output) }
            }
            ensureExecutable(dest)
            Log.i(TAG, "extracted assets engine → ${dest.absolutePath} exec=${dest.canExecute()}")
            if (dest.exists() && dest.length() > 0) dest else null
        } catch (e: Exception) {
            Log.e(TAG, "asset extract failed: ${e.message}")
            null
        }
    }

    private fun ensureExecutable(f: File) {
        try {
            f.setReadable(true, false)
            f.setExecutable(true, false)
            if (Build.VERSION.SDK_INT >= 21) {
                try {
                    Os.chmod(f.absolutePath, 493) // 0755
                } catch (_: Exception) {
                }
            }
        } catch (_: Exception) {
        }
    }

    private fun canTryExec(f: File): Boolean {
        // Android 10+ blocks exec from app data dirs even if chmod succeeds.
        if (Build.VERSION.SDK_INT >= 29) {
            val path = f.absolutePath
            if (path.contains("/files/") || path.contains("/cache/")) {
                Log.w(TAG, "skip exec candidate under data dir on API ${Build.VERSION.SDK_INT}: $path")
                return false
            }
        }
        return f.canExecute() || f.exists()
    }

    companion object {
        private const val TAG = "EngineRunner"
    }
}
