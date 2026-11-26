package app.aethernext

import android.util.Log
import android.webkit.JavascriptInterface
import org.json.JSONException
import org.json.JSONObject

/**
 * WebView bridge exposing the same command surface as Tauri desktop invoke().
 *
 * [originTrusted] is the T219 gate. A `JavascriptInterface` is attached to the
 * WebView, not to the page that was supposed to be in it: anything that can make
 * this WebView show another document — a redirect, a failed load that fell back to
 * the generated error page, a `data:`/`about:` navigation — inherits the object
 * and with it `connect`, `disconnect`, `save_settings` and the engine's config.
 * Every call therefore re-checks that the document actually loaded is one this APK
 * shipped, using the URL captured on the UI thread in `onPageStarted`.
 */
class AetherBridge(
    activity: MainActivity,
    private val session: SessionController,
    private val originTrusted: (() -> Boolean)? = null,
) {
    private val activityRef = java.lang.ref.WeakReference(activity)
    private val effectiveOriginTrusted: () -> Boolean =
        originTrusted ?: { activityRef.get()?.isBridgeOriginTrusted() ?: false }

    internal val commandWorker = java.util.concurrent.Executors.newCachedThreadPool { r ->
        Thread(r, "aether-bridge-cmd").apply { isDaemon = true }
    }

    private data class SettledResult(val envelope: JSONObject, val settledAt: Long)
    private val pendingResults = java.util.concurrent.ConcurrentHashMap<String, SettledResult>()
    private val sequence = java.util.concurrent.atomic.AtomicLong(0)

    internal fun shutdown() {
        commandWorker.shutdownNow()
        pendingResults.clear()
    }

    @JavascriptInterface
    fun invoke(cmd: String, argsJson: String): String {
        val trusted = try {
            effectiveOriginTrusted()
        } catch (e: Exception) {
            Log.w(TAG, "origin check threw, treating the caller as untrusted: ${e.message}")
            false
        }
        if (!trusted) {
            Log.e(TAG, "bridge call '$cmd' rejected: loaded page is not the packaged UI")
            return bridgeErr(
                "permission_denied",
                "Bridge call '$cmd' rejected: the loaded page is not the packaged Aether UI.",
                null,
            )
        }
        if (cmd in ASYNC_COMMANDS) return startAsync(cmd, argsJson)
        return runCommand(cmd, argsJson).toString()
    }

    /** Run one command and wrap its result, or its failure, in an envelope. */
    internal fun runCommand(cmd: String, argsJson: String): JSONObject = try {
        val args = if (argsJson.isBlank()) JSONObject() else JSONObject(argsJson)
        val data: Any? = dispatch(cmd, args)
        bridgeOkObject(data)
    } catch (e: SettingRejected) {
        bridgeErrObject("validation", e.message ?: "invalid setting", e.field)
    } catch (e: BridgeError) {
        bridgeErrObject(e.code, e.detail, e.field)
    } catch (e: JSONException) {
        // A malformed `settings` payload is a different conversation from a
        // failed connect: the caller sent something this side cannot parse.
        bridgeErrObject("encode", e.message ?: e.toString(), null)
    } catch (e: Exception) {
        bridgeErrObject("internal", e.message ?: e.toString(), null)
    }

    internal fun dispatch(cmd: String, args: JSONObject): Any? = when (cmd) {
        "get_settings" -> handleGetSettings()
        "save_settings" -> handleSaveSettings(args)
        "reset_settings" -> handleResetSettings()
        "get_state" -> session.getState().toJson()
        "is_admin" -> session.isVpnPrepared()
        "connect" -> handleConnect(args)
        "disconnect" -> handleDisconnect()
        "scan" -> handleScan(args)
        "stop_scan" -> handleStopScan()
        "test_connection" -> handleTestConnection(args)
        "check_update" -> handleCheckUpdate(args)
        "download_and_install_update" -> handleDownloadAndInstallUpdate(args)
        "app_info" -> handleAppInfo()
        "get_result" -> handleGetResult(args)
        "set_theme" -> handleSetTheme(args)
        else -> throw BridgeError("unknown_command", "unknown command $cmd")
    }

    /**
     * Hand [cmd] to the worker and return its token. The settled envelope — including
     * a rejection — is stored for [handleGetResult] to collect exactly once.
     */
    private fun startAsync(cmd: String, argsJson: String): String {
        pruneResults()
        val id = "$cmd#${sequence.incrementAndGet()}"
        val envelope = try {
            val args = if (argsJson.isBlank()) JSONObject() else JSONObject(argsJson)
            commandWorker.execute { settle(id, runCommand(cmd, args.toString())) }
            bridgeOkObject(JSONObject().put("pending", id).put("pollMs", POLL_INTERVAL_MS))
        } catch (e: JSONException) {
            // Nothing was dispatched, so the caller gets the parse error right now.
            bridgeErrObject("encode", e.message ?: e.toString(), null)
        } catch (e: java.util.concurrent.RejectedExecutionException) {
            bridgeErrObject("internal", "the bridge worker is shut down; $cmd was not started", null)
        }
        return envelope.toString()
    }

    internal fun settle(id: String, envelope: JSONObject) {
        pendingResults[id] = SettledResult(envelope, System.currentTimeMillis())
    }

    internal fun pendingResultIds(): Set<String> = pendingResults.keys.toSet()

    private fun handleGetResult(args: JSONObject): Any {
        val id = args.optString("id")
        pruneResults()
        val entry = if (id.isEmpty()) null else pendingResults.remove(id)
        if (entry == null) return JSONObject().put("state", "pending")
        return JSONObject().put("state", "done").put("envelope", entry.envelope)
    }

    private fun pruneResults(now: Long = System.currentTimeMillis()) {
        pendingResults.entries.removeIf { now - it.value.settledAt > RESULT_TTL_MS }
    }

    internal fun handleGetSettings(): Any =
        session.getSettings().toJson()

    internal fun handleSaveSettings(args: JSONObject): Any {
        val s = Settings.fromJson(args.getJSONObject("settings"))
        session.saveSettings(s)
        return JSONObject.NULL
    }

    internal fun handleResetSettings(): Any = session.resetSettings().toJson()

    internal fun handleConnect(args: JSONObject): Any {
        val s = if (args.has("settings")) {
            Settings.fromJson(args.getJSONObject("settings"))
        } else {
            session.getSettings()
        }
        val err = session.connect(s)
        return when {
            err == "VPN_PERMISSION_REQUIRED" -> {
                activityRef.get()?.requestVpnPermission()
                JSONObject.NULL
            }
            err != null -> throw BridgeError("connect_failed", err)
            else -> JSONObject.NULL
        }
    }

    internal fun handleDisconnect(): Any {
        val err = session.disconnect()
        if (err != null) throw BridgeError("stop_failed", err)
        return JSONObject.NULL
    }

    internal fun handleScan(args: JSONObject): Any {
        val protocol = args.optString("protocol", "masque-h3")
        val ipVersion = args.optString("ipVersion", "v4").lowercase()
        if (ipVersion !in setOf("v4", "v6", "dual", "both")) {
            throw SettingRejected("ipVersion", "Invalid ipVersion '$ipVersion'")
        }
        val concurrency = ScanLimits.clampConcurrency(args.optInt("concurrency", ScanLimits.MAX_CONCURRENCY_H3), protocol)
        val timeoutMs = ScanLimits.clampTimeout(args.optInt("timeoutMs", 6000), protocol)
        val noize = args.optString("noize", "off")
        val err = session.scan(protocol, ipVersion, concurrency, timeoutMs, noize, args.optString("runId", ""))
        if (err != null) throw BridgeError("scan_failed", err)
        return JSONObject.NULL
    }

    internal fun handleStopScan(): Any {
        session.stopScan()
        return JSONObject.NULL
    }

    internal fun handleTestConnection(args: JSONObject): Any {
        val s = if (args.has("settings")) {
            Settings.fromJson(args.getJSONObject("settings"))
        } else {
            session.getSettings()
        }
        return session.testConnection(s)
    }

    internal fun handleCheckUpdate(args: JSONObject): Any {
        val port = if (args.has("httpPort") && !args.isNull("httpPort")) args.optInt("httpPort") else null
        val useProxy = args.optBoolean("useLocalProxy", false)
        return session.checkUpdate(port, useProxy)
    }

    internal fun handleDownloadAndInstallUpdate(args: JSONObject): Any {
        val assetUrl = args.optString("assetUrl", "")
        val assetName = args.optString("assetName", "")
        val sha256 = if (args.has("sha256") && !args.isNull("sha256")) args.optString("sha256") else null
        val port = if (args.has("httpPort") && !args.isNull("httpPort")) args.optInt("httpPort") else null
        val useProxy = args.optBoolean("useLocalProxy", false)
        return session.downloadAndInstallUpdate(assetUrl, assetName, sha256, port, useProxy)
    }

    internal fun handleSetTheme(args: JSONObject): Any {
        val isDark = parseThemeArg(args.optString("theme", "light"))
        activityRef.get()?.applyNativeTheme(isDark)
        return JSONObject.NULL
    }

    internal fun handleAppInfo(): Any =
        JSONObject()
            .put("name", "Aether Next")
            .put("version", BuildConfig.VERSION_NAME)
            .put("author", "deathline94")
            .put("engine", "deathline94/aether-next")
            .put("platform", "android")

    companion object {
        private const val TAG = "AetherBridge"

        internal fun parseThemeArg(raw: String): Boolean = when {
            raw.equals("dark", ignoreCase = true) -> true
            raw.equals("light", ignoreCase = true) -> false
            else -> throw SettingRejected("theme", "Unsupported theme '$raw'; expected 'light' or 'dark'.")
        }

        /** How often the web layer may ask for a settled result. */
        const val POLL_INTERVAL_MS = 120L

        /** How long an uncollected result survives. */
        const val RESULT_TTL_MS = 120_000L

        /** Commands dispatched to [commandWorker] instead of the JavaBridge thread. */
        val ASYNC_COMMANDS: Set<String> = setOf(
            "connect",
            "disconnect",
            "scan",
            "test_connection",
            "check_update",
            "download_and_install_update",
        )
    }
}
