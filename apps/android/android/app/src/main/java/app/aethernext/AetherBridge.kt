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
    private val activity: MainActivity,
    private val session: SessionController,
    private val originTrusted: () -> Boolean = { activity.isBridgeOriginTrusted() },
) {
    /**
     * Commands that do not answer in milliseconds, and therefore may not run on the
     * thread that answers them.
     *
     * A `@JavascriptInterface` method with a return value is executed on the WebView's
     * JavaBridge thread, and Chromium's rendered JS waits on it: `connect` paid up to
     * 4.2 s of keystore retry (`ConfigKeyStore`) plus a 3 s process poll
     * (`EngineRunner.stopAndWait`) with the UI frozen, and `test_connection` a 12 s
     * blocking OkHttp call. The frozen page was not a slow spinner — `evaluateJavascript`
     * posts from the session queued up behind it, so the state stream arrived late or
     * after the thing it described had already changed.
     *
     * These now run on a worker, answer a token immediately, and the web layer polls
     * `get_result` for the settled envelope. Fast reads (`get_state` included) stay
     * synchronous so the UI can keep watching while a slow command is in flight.
     */
    internal val commandWorker = java.util.concurrent.Executors.newCachedThreadPool { r ->
        Thread(r, "aether-bridge-cmd").apply { isDaemon = true }
    }

    private val pendingResults = java.util.concurrent.ConcurrentHashMap<String, JSONObject>()
    private val resultAge = java.util.concurrent.ConcurrentHashMap<String, Long>()
    private val sequence = java.util.concurrent.atomic.AtomicLong(0)

    @JavascriptInterface
    fun invoke(cmd: String, argsJson: String): String {
        val trusted = try {
            originTrusted()
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
        "get_state" -> session.getState().toJson()
        "is_admin" -> session.isVpnPrepared()
        "connect" -> handleConnect(args)
        "disconnect" -> handleDisconnect()
        "scan" -> handleScan(args)
        "stop_scan" -> handleStopScan()
        "test_connection" -> handleTestConnection(args)
        "app_info" -> handleAppInfo()
        "get_result" -> handleGetResult(args)
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

    /** Publish a settled envelope for [id]. Visible for tests, which never start a WebView. */
    internal fun settle(id: String, envelope: JSONObject) {
        pendingResults[id] = envelope
        resultAge[id] = System.currentTimeMillis()
    }

    internal fun pendingResultIds(): Set<String> = pendingResults.keys.toSet()

    private fun handleGetResult(args: JSONObject): Any {
        val id = args.optString("id")
        pruneResults()
        val envelope = if (id.isEmpty()) null else pendingResults.remove(id)
        if (envelope == null) return JSONObject().put("state", "pending")
        resultAge.remove(id)
        return JSONObject().put("state", "done").put("envelope", envelope)
    }

    /**
     * A result nobody collected — a reload mid-command, a killed tab — must not
     * accumulate for the life of the process.
     */
    private fun pruneResults(now: Long = System.currentTimeMillis()) {
        for ((id, at) in resultAge) {
            if (now - at > RESULT_TTL_MS) {
                resultAge.remove(id)
                pendingResults.remove(id)
            }
        }
    }

    internal fun handleGetSettings(): Any =
        session.getSettings().toJson()

    internal fun handleSaveSettings(args: JSONObject): Any {
        val s = Settings.fromJson(args.getJSONObject("settings"))
        session.saveSettings(s)
        return JSONObject.NULL
    }

    internal fun handleConnect(args: JSONObject): Any {
        val s = if (args.has("settings")) {
            Settings.fromJson(args.getJSONObject("settings"))
        } else {
            session.getSettings()
        }
        val err = session.connect(s)
        return when {
            err == "VPN_PERMISSION_REQUIRED" -> {
                activity.requestVpnPermission()
                // Permission pending - not a hard failure
                JSONObject.NULL
            }
            err != null -> throw BridgeError("connect_failed", err)
            else -> JSONObject.NULL
        }
    }

    internal fun handleDisconnect(): Any {
        // T206: "I asked the tunnel to stop" is not "the tunnel stopped". The
        // message says what is still up and what to do about it, and it travels as
        // a coded rejection so the UI can show it instead of a green "Ready".
        val err = session.disconnect()
        if (err != null) throw BridgeError("stop_failed", err)
        return JSONObject.NULL
    }

    internal fun handleScan(args: JSONObject): Any {
        val protocol = args.optString("protocol", "masque-h3")
        val ipVersion = args.optString("ipVersion", "v4")
        val concurrency = ScanLimits.clampConcurrency(args.optInt("concurrency", 250))
        // The single clamp. The UI used to advertise 100-30000 ms while this line
        // quietly coerced the number to >=3000 (>=6000 for MASQUE), so the two sides
        // disagreed about what the user had asked for; both now read [ScanLimits].
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

    internal fun handleAppInfo(): Any =
        JSONObject()
            .put("name", "Aether Next")
            .put("version", BuildConfig.VERSION_NAME)
            .put("author", "deathline94")
            .put("engine", "deathline94/aether-next")
            .put("platform", "android")

    companion object {
        private const val TAG = "AetherBridge"

        /** How often the web layer may ask for a settled result. */
        const val POLL_INTERVAL_MS = 120L

        /** How long an uncollected result survives. */
        const val RESULT_TTL_MS = 120_000L

        /** Commands dispatched to [commandWorker] instead of the JavaBridge thread. */
        val ASYNC_COMMANDS: Set<String> = setOf("connect", "disconnect", "scan", "test_connection")
    }
}
