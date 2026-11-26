package app.aethernext

import android.annotation.SuppressLint
import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.util.Log
import android.view.View
import android.webkit.ConsoleMessage
import android.webkit.WebChromeClient
import android.webkit.WebResourceRequest
import android.webkit.WebView
import android.widget.LinearLayout
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.app.AppCompatDelegate
import androidx.core.graphics.Insets
import androidx.core.view.ViewCompat
import androidx.core.view.WindowCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.view.WindowInsetsControllerCompat
import androidx.webkit.WebResourceErrorCompat
import androidx.webkit.WebViewAssetLoader
import androidx.webkit.WebViewClientCompat
import androidx.webkit.WebViewFeature
import org.json.JSONObject
import java.io.ByteArrayInputStream

class MainActivity : AppCompatActivity() {
    private lateinit var webView: WebView
    private lateinit var contentRoot: LinearLayout
    private lateinit var statusBarInset: View
    private lateinit var bottomBarInset: View
    private lateinit var session: SessionController

    @Volatile
    private var darkTheme = false
    private var imeVisible = false

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

    @Volatile
    private var pageFinished = false

    private val preLoadEvents = java.util.concurrent.ConcurrentLinkedQueue<Pair<String, JSONObject>>()
    private lateinit var bridge: AetherBridge

    @SuppressLint("SetJavaScriptEnabled")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        darkTheme = getSharedPreferences("aether_ui_prefs", MODE_PRIVATE)
            .getString("ui_theme", "light") == "dark"
        pendingConnectAfterVpn = savedInstanceState?.getBoolean(KEY_PENDING_VPN_CONNECT, false) ?: false
        // The uncaught-exception forwarder is installed once, from AetherApp.
        // Chaining it here re-wrapped the default handler on every activity
        // create, so a destroyed activity's closure stayed in the chain forever.

        // Helpful when diagnosing UI blanks on emulators / LDPlayer.
        WebView.setWebContentsDebuggingEnabled(BuildConfig.DEBUG)

        // Target SDK 36 draws behind system bars. Paint dedicated inset views matching
        // our theme chrome (status bar = canvas, bottom nav bar = panel) so dark mode
        // updates system bars seamlessly instead of leaving bright white stripes.
        WindowCompat.setDecorFitsSystemWindows(window, false)

        val initialCanvas = getColor(if (darkTheme) R.color.app_canvas_dark else R.color.app_canvas)
        val initialNav = getColor(if (darkTheme) R.color.app_nav_dark else R.color.app_nav_light)

        statusBarInset = View(this).apply { setBackgroundColor(initialCanvas) }
        bottomBarInset = View(this).apply { setBackgroundColor(initialNav) }
        webView = WebView(this).apply {
            setBackgroundColor(initialCanvas)
            overScrollMode = View.OVER_SCROLL_NEVER
            isVerticalScrollBarEnabled = false
            isHorizontalScrollBarEnabled = false
        }
        contentRoot = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(initialCanvas)
            addView(statusBarInset, LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, 0))
            addView(webView, LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, 0, 1f))
            addView(bottomBarInset, LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, 0))
        }
        ViewCompat.setOnApplyWindowInsetsListener(contentRoot) { view, insets ->
            val types = WindowInsetsCompat.Type.systemBars() or WindowInsetsCompat.Type.displayCutout()
            val bars = insets.getInsets(types)
            // The keyboard is consumed into the same bottom spacer: with decor-fits off,
            // adjustResize no longer resizes the window, so nothing else shrank the
            // WebView and the Settings tab's port fields and sticky save dock sat
            // behind the soft keyboard. Max with the nav bar so an open IME replaces
            // the navigation inset rather than stacking on top of it.
            val ime = insets.getInsets(WindowInsetsCompat.Type.ime())
            imeVisible = ime.bottom > bars.bottom
            val bottom = maxOf(bars.bottom, ime.bottom)
            view.setPadding(bars.left, 0, bars.right, 0)
            if (statusBarInset.layoutParams.height != bars.top) {
                statusBarInset.layoutParams = LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.MATCH_PARENT,
                    bars.top,
                )
            }
            if (bottomBarInset.layoutParams.height != bottom) {
                bottomBarInset.layoutParams = LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.MATCH_PARENT,
                    bottom,
                )
            }
            val canvasColor = getColor(if (darkTheme) R.color.app_canvas_dark else R.color.app_canvas)
            val navColor = getColor(if (darkTheme) R.color.app_nav_dark else R.color.app_nav_light)
            statusBarInset.setBackgroundColor(canvasColor)
            bottomBarInset.setBackgroundColor(if (imeVisible) canvasColor else navColor)
            // Zero the consumed types before they reach WebView: newer WebView
            // versions also expose them as CSS safe-area values, and both the bar
            // and the keyboard inset have already been turned into spacers here.
            WindowInsetsCompat.Builder(insets)
                .setInsets(types, Insets.NONE)
                .setInsets(WindowInsetsCompat.Type.ime(), Insets.NONE)
                .build()
        }
        setContentView(contentRoot)
        applyNativeTheme(darkTheme)
        ViewCompat.requestApplyInsets(contentRoot)

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
                return !isTrustedUiUrl(request.url.toString(), APP_HOST, UI_PATH_PREFIX)
            }

            override fun shouldInterceptRequest(
                view: WebView,
                request: WebResourceRequest,
            ): android.webkit.WebResourceResponse? {
                if (isTrustedUiUrl(request.url.toString(), APP_HOST, UI_PATH_PREFIX)) {
                    return assetLoader.shouldInterceptRequest(request.url)
                }
                Log.w(TAG, "blocked untrusted WebView resource: ${request.url}")
                return android.webkit.WebResourceResponse(
                    "text/plain", "UTF-8", 403, "Forbidden", emptyMap(), ByteArrayInputStream(ByteArray(0)),
                )
            }

            override fun onPageStarted(view: WebView, url: String, favicon: android.graphics.Bitmap?) {
                loadedUrl = url
                pageFinished = false
            }

            override fun onPageFinished(view: WebView, url: String) {
                Log.i(TAG, "page finished: $url")
                pageFinished = true
                emitToJs("session://state", session.getState().toJson())
                while (true) {
                    val queued = preLoadEvents.poll() ?: break
                    emitToJs(queued.first, queued.second)
                }
                surfaceBootHandoff()
            }

            override fun onRenderProcessGone(
                view: WebView,
                detail: android.webkit.RenderProcessGoneDetail,
            ): Boolean {
                Log.e(TAG, "WebView render process gone (didCrash=${detail.didCrash()}); reloading UI")
                if (isDestroyed || isFinishing) return true
                pageFinished = false
                loadedUrl = null
                runOnUiThread {
                    if (!isDestroyed && !isFinishing && ::webView.isInitialized) {
                        val entry = "https://$APP_HOST$UI_PATH_PREFIX" + "index.html"
                        loadedUrl = entry
                        webView.loadUrl(entry)
                    }
                }
                return true
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
        }

        val entry = "https://$APP_HOST$UI_PATH_PREFIX" + "index.html"
        bridge = AetherBridge(this, session)
        webView.addJavascriptInterface(bridge, "AetherAndroid")
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
            val prefs = getSharedPreferences("aether_ui_prefs", MODE_PRIVATE)
            if (prefs.getBoolean("notif_asked_once", false) && !shouldShowRequestPermissionRationale(perm)) {
                return
            }
            prefs.edit().putBoolean("notif_asked_once", true).apply()
            requestPermissions(arrayOf(perm), REQ_NOTIFICATIONS)
        }
    }

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

    fun applyNativeTheme(dark: Boolean) {
        darkTheme = dark
        getSharedPreferences("aether_ui_prefs", MODE_PRIVATE)
            .edit()
            .putString("ui_theme", if (dark) "dark" else "light")
            .apply()
        runOnUiThread {
            if (isDestroyed || isFinishing) return@runOnUiThread
            val canvasColor = getColor(if (dark) R.color.app_canvas_dark else R.color.app_canvas)
            val navColor = getColor(if (dark) R.color.app_nav_dark else R.color.app_nav_light)
            window.decorView.setBackgroundColor(canvasColor)
            if (::contentRoot.isInitialized) contentRoot.setBackgroundColor(canvasColor)
            if (::statusBarInset.isInitialized) statusBarInset.setBackgroundColor(canvasColor)
            if (::bottomBarInset.isInitialized) {
                bottomBarInset.setBackgroundColor(if (imeVisible) canvasColor else navColor)
            }
            if (::webView.isInitialized) webView.setBackgroundColor(canvasColor)
            @Suppress("DEPRECATION")
            window.statusBarColor = canvasColor
            @Suppress("DEPRECATION")
            window.navigationBarColor = navColor
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                window.isNavigationBarContrastEnforced = false
            }
            WindowInsetsControllerCompat(window, window.decorView).apply {
                isAppearanceLightStatusBars = !dark
                isAppearanceLightNavigationBars = !dark
            }
            val targetMode = if (dark) {
                AppCompatDelegate.MODE_NIGHT_YES
            } else {
                AppCompatDelegate.MODE_NIGHT_NO
            }
            if (delegate.localNightMode != targetMode) {
                delegate.localNightMode = targetMode
            }
        }
    }

    private fun showLoadError(description: String, url: String) {
        loadedUrl = null
        pageFinished = false
        webView.removeJavascriptInterface("AetherAndroid")
        val bg = if (darkTheme) "#0B1117" else "#F4F7FA"
        val fg = if (darkTheme) "#E6EEF6" else "#0D1B2A"
        val accent = if (darkTheme) "#38C5B6" else "#0F6E6E"
        val html = """
            <!DOCTYPE html><html><head>
            <meta charset="utf-8"/>
            <meta name="viewport" content="width=device-width,initial-scale=1"/>
            <style>
              body{font-family:sans-serif;background:$bg;color:$fg;padding:24px;line-height:1.45}
              code{color:$accent;word-break:break-all}
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

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        outState.putBoolean(KEY_PENDING_VPN_CONNECT, pendingConnectAfterVpn)
    }

    private fun attachUiSink() {
        session.attachUi(this) { event, payload ->
            if (!pageFinished) {
                if (preLoadEvents.size < 256) preLoadEvents.add(event to payload)
                return@attachUi
            }
            runOnUiThread { emitToJs(event, payload) }
        }
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
        if (isDestroyed || isFinishing || !::webView.isInitialized) return
        val ev = JSONObject.quote(event)
        val pl = JSONObject.quote(payload.toString())
        val js = "window.__aetherEmit && window.__aetherEmit($ev, $pl);"
        webView.evaluateJavascript(js, null)
    }

    override fun onDestroy() {
        if (::session.isInitialized) {
            val lastUi = session.detachUi(this)
            // Keep an already-running VPN tunnel alive across Back/Recents; only
            // stop if a session died before connecting or user asked to exit.
            if (lastUi && !isChangingConfigurations && session.getState().status == "disconnected") {
                val controller = session
                teardownExecutor.execute {
                    try {
                        controller.shutdownHeadless()
                    } catch (e: Exception) {
                        Log.w(TAG, "headless teardown failed: ${e.message}", e)
                    }
                }
            }
        }
        if (::bridge.isInitialized) {
            bridge.shutdown()
        }
        connectExecutor.shutdownNow()
        teardownExecutor.shutdown()
        if (::webView.isInitialized) {
            webView.removeJavascriptInterface("AetherAndroid")
            webView.destroy()
        }
        loadedUrl = null
        pageFinished = false
        super.onDestroy()
    }

    companion object {
        private const val TAG = "AetherMain"
        private const val KEY_PENDING_VPN_CONNECT = "pending_connect_after_vpn"
        private const val REQ_VPN = 1001
        private const val REQ_NOTIFICATIONS = 1002
        private const val APP_HOST = "appassets.androidplatform.net"

        /** Everything the shell loads lives under here; see [isBridgeOriginTrusted]. */
        private const val UI_PATH_PREFIX = "/assets/www/"
    }
}
