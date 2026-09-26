package app.aethernext

import android.annotation.SuppressLint
import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.util.Log
import android.webkit.ConsoleMessage
import android.webkit.WebChromeClient
import android.webkit.WebResourceRequest
import android.webkit.WebView
import android.widget.FrameLayout
import androidx.appcompat.app.AppCompatActivity
import androidx.core.graphics.Insets
import androidx.core.view.ViewCompat
import androidx.core.view.WindowCompat
import androidx.core.view.WindowInsetsCompat
import androidx.webkit.WebResourceErrorCompat
import androidx.webkit.WebViewAssetLoader
import androidx.webkit.WebViewClientCompat
import androidx.webkit.WebViewFeature
import org.json.JSONObject
import java.io.ByteArrayInputStream

class MainActivity : AppCompatActivity() {
    private lateinit var webView: WebView
    private lateinit var session: SessionController

    /**
     * Set when a connect is waiting on the VPN consent sheet.
     *
     * Main thread only, and it has to stay that way: [requestVpnPermission] is called
     * from the WebView's JavaBridge thread and `onActivityResult` on the main one, so
     * as a plain field this was a cross-thread write whose value the reader was free
     * never to see — the consent result could come back and find nothing pending, or
     * the reverse. Every entry point now marshals to the main thread first, so the
     * flag has exactly one owner thread.
     */
    private var pendingConnectAfterVpn = false

    /** Runs the headless teardown off the main thread; see [onDestroy]. */
    private val teardownExecutor = java.util.concurrent.Executors.newSingleThreadExecutor { r ->
        Thread(r, "aether-teardown").apply { isDaemon = true }
    }

    /**
     * Runs the post-consent reconnect off the main thread; see [retryConnect].
     * Single thread so re-drive attempts stay ordered behind each other.
     */
    private val connectExecutor = java.util.concurrent.Executors.newSingleThreadExecutor { r ->
        Thread(r, "aether-connect").apply { isDaemon = true }
    }

    /**
     * The document currently loaded, captured on the UI thread in `onPageStarted`
     * and read from the JavaBridge thread by [AetherBridge]. `WebView.getUrl()`
     * must not be called off the UI thread, so the shell keeps its own volatile
     * copy for the origin gate (T219).
     */
    @Volatile
    private var loadedUrl: String? = null

    @SuppressLint("SetJavaScriptEnabled")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // The uncaught-exception forwarder is installed once, from AetherApp.
        // Chaining it here re-wrapped the default handler on every activity
        // create, so a destroyed activity's closure stayed in the chain forever.

        // Helpful when diagnosing UI blanks on emulators / LDPlayer.
        WebView.setWebContentsDebuggingEnabled(BuildConfig.DEBUG)

        // Target SDK 36 draws behind system bars. Keep the WebView viewport inside
        // the status/navigation bars so its sticky header and bottom tabs cannot
        // overlap the system UI. Zero the handled insets before they reach WebView:
        // newer WebView versions also expose them as CSS safe-area values.
        WindowCompat.setDecorFitsSystemWindows(window, false)

        webView = WebView(this).apply {
            // The theme's canvas, not a second copy of the hex: this is the colour
            // visible before the WebView's own stylesheet paints, and a literal
            // here is how the chrome drifted three shades apart.
            setBackgroundColor(getColor(R.color.app_canvas))
        }
        val content = FrameLayout(this).apply {
            setBackgroundColor(getColor(R.color.app_canvas))
            addView(webView, FrameLayout.LayoutParams(-1, -1))
        }
        ViewCompat.setOnApplyWindowInsetsListener(content) { view, insets ->
            val types = WindowInsetsCompat.Type.systemBars() or WindowInsetsCompat.Type.displayCutout()
            val bars = insets.getInsets(types)
            // The keyboard is consumed into the same padding: with decor-fits off,
            // adjustResize no longer resizes the window, so nothing else shrank the
            // WebView and the Settings tab's port fields and sticky save dock sat
            // behind the soft keyboard. Max with the nav bar so an open IME replaces
            // the navigation inset rather than stacking on top of it.
            val ime = insets.getInsets(WindowInsetsCompat.Type.ime())
            val bottom = maxOf(bars.bottom, ime.bottom)
            view.setPadding(bars.left, bars.top, bars.right, bottom)
            // Zero the consumed types before they reach WebView: newer WebView
            // versions also expose them as CSS safe-area values, and both the bar
            // and the keyboard inset have already been turned into padding here.
            WindowInsetsCompat.Builder(insets)
                .setInsets(types, Insets.NONE)
                .setInsets(WindowInsetsCompat.Type.ime(), Insets.NONE)
                .build()
        }
        setContentView(content)
        ViewCompat.requestApplyInsets(content)

        // The sink belongs to *this* WebView, so it is registered per owner: the
        // session is a process singleton, and handing its one emitter to whichever
        // activity happened to start first is what let a task swipe silence a running
        // tunnel (T2xx).
        session = SessionController.get(this) { _, _ -> }
        attachUiSink()

        // file:///android_asset/ + ES modules often fail (blank white page).
        // Serve assets via the official https virtual host instead.
        val assetLoader = WebViewAssetLoader.Builder()
            .addPathHandler("/assets/", WebViewAssetLoader.AssetsPathHandler(this))
            .build()

        webView.settings.apply {
            javaScriptEnabled = true
            domStorageEnabled = true
            databaseEnabled = false
            allowFileAccess = false
            allowContentAccess = false
            mediaPlaybackRequiresUserGesture = false
            // Needed so relative module imports resolve correctly.
            useWideViewPort = true
            loadWithOverviewMode = true
        }

        webView.webChromeClient = object : WebChromeClient() {
            override fun onConsoleMessage(consoleMessage: ConsoleMessage?): Boolean {
                // The packaged UI is the engine's stdout for a user who has no
                // terminal: echoing every line it logs into logcat in a release build
                // puts probe targets, endpoints and any future diagnostic in a
                // world-readable buffer. Debug builds keep the flood.
                if (consoleMessage != null && BuildConfig.DEBUG) {
                    Log.d(
                        TAG,
                        "js ${consoleMessage.messageLevel()}: ${consoleMessage.message()} " +
                            "(${consoleMessage.sourceId()}:${consoleMessage.lineNumber()})",
                    )
                }
                return true
            }
        }

        webView.webViewClient = object : WebViewClientCompat() {
            override fun shouldOverrideUrlLoading(view: WebView, request: WebResourceRequest): Boolean {
                return request.url.scheme != "https" || request.url.host != APP_HOST
            }

            override fun shouldInterceptRequest(
                view: WebView,
                request: WebResourceRequest,
            ): android.webkit.WebResourceResponse? {
                if (request.url.scheme == "https" && request.url.host == APP_HOST) {
                    return assetLoader.shouldInterceptRequest(request.url)
                }
                Log.w(TAG, "blocked untrusted WebView resource: ${request.url}")
                return android.webkit.WebResourceResponse(
                    "text/plain", "UTF-8", 403, "Forbidden", emptyMap(), ByteArrayInputStream(ByteArray(0)),
                )
            }

            override fun onPageStarted(view: WebView, url: String, favicon: android.graphics.Bitmap?) {
                // Runs on the UI thread before any script in that document, so the
                // bridge gate can never see a URL later than the page executing.
                loadedUrl = url
            }

            override fun onPageFinished(view: WebView, url: String) {
                Log.i(TAG, "page finished: $url")
                emitToJs("session://state", session.getState().toJson())
                surfaceBootHandoff()
            }

            override fun onReceivedError(
                view: WebView,
                request: WebResourceRequest,
                error: WebResourceErrorCompat,
            ) {
                val desc =
                    if (WebViewFeature.isFeatureSupported(WebViewFeature.WEB_RESOURCE_ERROR_GET_DESCRIPTION)) {
                        error.description?.toString() ?: "unknown error"
                    } else {
                        "load error"
                    }
                if (request.isForMainFrame) {
                    Log.e(TAG, "main frame error: $desc url=${request.url}")
                    showLoadError(desc, request.url.toString())
                } else {
                    Log.w(TAG, "resource error: $desc url=${request.url}")
                }
            }

            @Deprecated("Deprecated in Java")
            override fun onReceivedError(
                view: WebView?,
                errorCode: Int,
                description: String?,
                failingUrl: String?,
            ) {
                Log.e(TAG, "legacy error $errorCode $description $failingUrl")
            }
        }

        // Maps to assets/www/index.html → relative ./assets/*.js load correctly.
        val entry = "https://$APP_HOST$UI_PATH_PREFIX" + "index.html"
        // Only expose bridge after client is locked to appassets host.
        webView.addJavascriptInterface(
            AetherBridge(this, session) { isBridgeOriginTrusted() },
            "AetherAndroid",
        )
        Log.i(TAG, "loading $entry")
        loadedUrl = entry
        webView.loadUrl(entry)

        // Android 13+ suppresses the foreground-service notification unless this
        // runtime permission is granted, so request it up front. Denial is
        // non-fatal (the tunnel still runs; the notification just won't show).
        maybeRequestNotificationPermission()
    }

    /**
     * Whether the page in the WebView may use the bridge. The document that has
     * not been reached through `loadUrl`/`loadDataWithBaseURL` of a packaged asset
     * — including the error page below, which is why that call clears this first —
     * gets a rejection instead of a session.
     */
    internal fun isBridgeOriginTrusted(): Boolean =
        isTrustedUiUrl(loadedUrl, APP_HOST, UI_PATH_PREFIX)

    private fun maybeRequestNotificationPermission() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) return
        val perm = android.Manifest.permission.POST_NOTIFICATIONS
        if (checkSelfPermission(perm) != android.content.pm.PackageManager.PERMISSION_GRANTED) {
            requestPermissions(arrayOf(perm), REQ_NOTIFICATIONS)
        }
    }

    /**
     * The answer to [maybeRequestNotificationPermission].
     *
     * There was none, which mattered because a foreground service whose notification is
     * suppressed is still a foreground service: the tunnel runs, the system counts it
     * against the user's battery, and nothing on screen says so. A denial is therefore
     * reported into the UI, where the user can act on it.
     */
    @Deprecated("Deprecated in Java")
    override fun onRequestPermissionsResult(
        requestCode: Int,
        permissions: Array<out String>,
        grantResults: IntArray,
    ) {
        @Suppress("DEPRECATION")
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode != REQ_NOTIFICATIONS) return
        val denied = grantResults.isEmpty() ||
            grantResults[0] != android.content.pm.PackageManager.PERMISSION_GRANTED
        if (!denied) return
        val message = "Notifications are off: the VPN foreground service keeps running with no " +
            "visible notification, so nothing on this device shows that traffic is being routed. " +
            "Enable notifications in system Settings to keep the tunnel visible."
        Log.w(TAG, message)
        if (::session.isInitialized) session.emitWarn(message)
    }

    /**
     * The "UI failed to load" page.
     *
     * Two hardening rules live here (T219): the bridge is detached *before* this
     * document can run — the error page used to inherit a live `AetherAndroid`
     * object, which is the actual exploit path — and both interpolated values are
     * HTML-escaped, because `error.description` and the failing URL come from
     * whatever made the navigation fail, not from us.
     */
    private fun showLoadError(description: String, url: String) {
        loadedUrl = null
        webView.removeJavascriptInterface("AetherAndroid")
        val html = """
            <!DOCTYPE html><html><head>
            <meta charset="utf-8"/>
            <meta name="viewport" content="width=device-width,initial-scale=1"/>
            <style>
              body{font-family:sans-serif;background:#0d1113;color:#e8edf0;padding:24px;line-height:1.45}
              code{color:#66e3a4;word-break:break-all}
              h1{font-size:18px;margin:0 0 12px}
            </style></head><body>
            <h1>UI failed to load</h1>
            <p><code>${escapeHtml(description)}</code></p>
            <p>url: <code>${escapeHtml(url)}</code></p>
            <p>Reinstall from Latest, or check that assets/www is packaged in the APK.</p>
            </body></html>
        """.trimIndent()
        webView.loadDataWithBaseURL(null, html, "text/html", "UTF-8", null)
    }

    /**
     * "Launch at login" cannot start an activity from the boot receiver on API 29+,
     * and its notification is dropped outright when the permission is denied. When
     * that happened the user saw nothing at all until they opened the app, so the
     * handoff is replayed here as a visible log line once the UI is listening.
     */
    private fun surfaceBootHandoff() {
        val pending = BootHandoff.consumePendingStart(this) ?: return
        Log.i(TAG, "replaying boot handoff: $pending")
        if (::session.isInitialized) session.emitLog(pending)
    }

    /**
     * Ask for the VPN permission.
     *
     * Called from the bridge — that is, from the WebView's JavaBridge thread — and
     * `startActivityForResult` on anything but the UI thread is both a crash risk and
     * the reason the consent sheet used to appear at an arbitrary point in the
     * lifecycle. The whole body is therefore posted, and the flag it owns is only ever
     * touched on the main thread.
     */
    fun requestVpnPermission() {
        runOnUiThread {
            pendingConnectAfterVpn = true
            val intent = try {
                VpnService.prepare(this)
            } catch (e: Exception) {
                // A prepared-check that throws must not be reported as "granted": the
                // connect would then hang waiting for a tunnel nobody authorised.
                Log.e(TAG, "VpnService.prepare failed: ${e.message}", e)
                pendingConnectAfterVpn = false
                emitToJs(
                    "session://state",
                    RuntimeState(
                        status = "error",
                        detail = "VPN permission could not be checked: ${e.message ?: e.javaClass.simpleName}",
                        pid = null,
                        endpoint = null,
                    ).toJson(),
                )
                return@runOnUiThread
            }
            if (intent != null) {
                @Suppress("DEPRECATION")
                startActivityForResult(intent, REQ_VPN)
            } else {
                retryConnect()
            }
        }
    }

    private fun attachUiSink() {
        session.attachUi(this) { event, payload -> runOnUiThread { emitToJs(event, payload) } }
    }

    override fun onResume() {
        super.onResume()
        // A configuration change or a re-created activity replaces its WebView; the
        // sink has to follow it, or events go to a destroyed page forever.
        if (::session.isInitialized) attachUiSink()
    }

    @Deprecated("Deprecated in Java")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == REQ_VPN) {
            if (resultCode == Activity.RESULT_OK && pendingConnectAfterVpn) {
                retryConnect()
            } else if (resultCode != Activity.RESULT_OK) {
                emitToJs(
                    "session://state",
                    RuntimeState(
                        status = "error",
                        detail = "VPN permission denied",
                        pid = null,
                        endpoint = null,
                    ).toJson(),
                )
            }
            pendingConnectAfterVpn = false
        }
    }

    /**
     * Re-drive the connect that was interrupted by the VPN consent sheet.
     *
     * [SessionController.connect] forks the engine process and can block for
     * seconds (KeyStore handoff retries, `stopAndWait` on a stopping child), and
     * both callers — the onActivityResult callback and the already-prepared
     * branch of [requestVpnPermission] — run on the main thread. Doing this
     * inline is how a fresh install ANRs at the exact moment the user grants
     * consent; the work belongs on [connectExecutor], with the state emission
     * posted back to the UI thread for the WebView.
     */
    private fun retryConnect() {
        val controller = session
        connectExecutor.execute {
            val s = controller.getSettings()
            val err = controller.connect(s)
            if (err != null && err != "VPN_PERMISSION_REQUIRED") {
                runOnUiThread {
                    emitToJs(
                        "session://state",
                        RuntimeState(status = "error", detail = err, pid = null, endpoint = null).toJson(),
                    )
                }
            }
        }
    }

    private fun emitToJs(event: String, payload: JSONObject) {
        if (!::webView.isInitialized) return
        val ev = JSONObject.quote(event)
        val pl = JSONObject.quote(payload.toString())
        val js = "window.__aetherEmit && window.__aetherEmit($ev, $pl);"
        webView.evaluateJavascript(js, null)
    }

    override fun onDestroy() {
        // Detach *this* activity's sink and, if it was the last one, stop the tunnel —
        // off the main thread, because a full teardown waits on the engine child and on
        // hev. The previous code called `setEmitter { _, _ -> }` on a process singleton:
        // it silenced every listener, so the engine and a full-device VPN kept running
        // with nothing attached to see or stop them (T2xx).
        if (::session.isInitialized) {
            val lastUi = session.detachUi(this)
            if (lastUi && !isChangingConfigurations) {
                val executor = teardownExecutor
                val controller = session
                executor.execute {
                    try {
                        controller.shutdownHeadless()
                    } catch (e: Exception) {
                        Log.w(TAG, "headless teardown failed: ${e.message}", e)
                    }
                }
            }
        }
        if (::webView.isInitialized) {
            webView.removeJavascriptInterface("AetherAndroid")
            webView.destroy()
        }
        loadedUrl = null
        super.onDestroy()
    }

    companion object {
        private const val TAG = "AetherMain"
        private const val REQ_VPN = 1001
        private const val REQ_NOTIFICATIONS = 1002
        private const val APP_HOST = "appassets.androidplatform.net"

        /** Everything the shell loads lives under here; see [isBridgeOriginTrusted]. */
        private const val UI_PATH_PREFIX = "/assets/www/"
    }
}
