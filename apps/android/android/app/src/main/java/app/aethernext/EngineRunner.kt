package app.aethernext

import android.content.Context
import android.os.Build
import android.util.Log
import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

/**
 * Spawns the packaged `aether` engine binary with the same env contract as desktop.
 */
class EngineRunner(
    private val context: Context,
    private val onLine: (String) -> Unit,
    private val onExit: (Int?) -> Unit,
) {
    private val processRef = AtomicReference<Process?>(null)
    private val running = AtomicBoolean(false)

    fun isRunning(): Boolean = running.get()

    fun pid(): Int? {
        val p = processRef.get() ?: return null
        // Process.pid() is API 33+; use reflection for older devices.
        return try {
            val m = p.javaClass.getMethod("pid")
            (m.invoke(p) as? Int)
        } catch (_: Exception) {
            null
        }
    }

    fun start(settings: Settings): String? {
        if (!running.compareAndSet(false, true)) {
            return "Aether is already running"
        }
        return try {
            val binary = resolveEngine(settings.enginePath)
                ?: return "aether engine binary not found. Build for Android and place in jniLibs or assets."
            val configDir = File(context.filesDir, "config").apply { mkdirs() }
            val configPath = File(configDir, "aether.toml").absolutePath

            val pb = ProcessBuilder(binary.absolutePath).apply {
                directory(binary.parentFile)
                redirectErrorStream(true)
                environment().apply {
                    put("AETHER_PROTOCOL", settings.protocol)
                    put("AETHER_SCAN", settings.scanMode)
                    put("AETHER_IP", settings.ipVersion)
                    put("AETHER_NOIZE", settings.noize)
                    put("AETHER_SOCKS", "127.0.0.1:${settings.socksPort}")
                    put("AETHER_HTTP", "127.0.0.1:${settings.httpPort}")
                    put("AETHER_CONFIG", configPath)
                    put(
                        "AETHER_MASQUE_HTTP2",
                        if (settings.transport == "h2") "1" else "0",
                    )
                    put(
                        "AETHER_TUN",
                        if (settings.routingMode == "tun") "1" else "0",
                    )
                    put("AETHER_WG_NO_PROFILE_RETRY", "1")
                    put("RUST_LOG", "info")
                    put("HOME", context.filesDir.absolutePath)
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
                    Log.w(TAG, "reader ended: ${e.message}")
                } finally {
                    val code = try {
                        proc.waitFor()
                    } catch (_: Exception) {
                        null
                    }
                    running.set(false)
                    processRef.set(null)
                    onExit(code)
                }
            }, "aether-engine-io").start()
            null
        } catch (e: Exception) {
            running.set(false)
            processRef.set(null)
            "Could not start engine: ${e.message}"
        }
    }

    fun stop() {
        val p = processRef.getAndSet(null) ?: return
        try {
            p.destroy()
            // Give graceful exit a moment, then force.
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
        if (configured.isNotBlank()) {
            val f = File(configured)
            if (f.exists() && f.canExecute()) return f
        }
        // Extracted copy in files dir (preferred for execute bit).
        val extracted = File(context.filesDir, "engine/aether")
        if (extracted.exists()) {
            extracted.setExecutable(true, false)
            if (extracted.canExecute()) return extracted
        }
        // Native library dir (if shipped as libaether.so renamed usage)
        val libDir = File(context.applicationInfo.nativeLibraryDir)
        listOf("aether", "libaether.so").forEach { name ->
            val f = File(libDir, name)
            if (f.exists()) {
                // Copy to filesDir so we can chmod +x consistently
                return extractFromFile(f, extracted)
            }
        }
        // assets/engine/aether
        return try {
            context.assets.open("engine/aether").use { input ->
                extracted.parentFile?.mkdirs()
                extracted.outputStream().use { output -> input.copyTo(output) }
                extracted.setExecutable(true, false)
                if (extracted.exists()) extracted else null
            }
        } catch (_: Exception) {
            null
        }
    }

    private fun extractFromFile(src: File, dest: File): File? {
        return try {
            dest.parentFile?.mkdirs()
            src.inputStream().use { input ->
                dest.outputStream().use { output -> input.copyTo(output) }
            }
            dest.setExecutable(true, false)
            dest
        } catch (e: Exception) {
            Log.e(TAG, "extract failed: ${e.message}")
            null
        }
    }

    companion object {
        private const val TAG = "EngineRunner"
    }
}
