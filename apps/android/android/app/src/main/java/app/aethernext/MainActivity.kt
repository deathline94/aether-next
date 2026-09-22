package app.aethernext

import android.annotation.SuppressLint
import android.app.Activity
import android.content.Intent
import android.graphics.Color
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.util.Log
import android.webkit.ConsoleMessage
import android.webkit.WebChromeClient
import android.webkit.WebResourceRequest
import android.webkit.WebView
import androidx.appcompat.app.AppCompatActivity
import androidx.webkit.WebResourceErrorCompat
import androidx.webkit.WebViewAssetLoader
import androidx.webkit.WebViewClientCompat
import androidx.webkit.WebViewFeature
import org.json.JSONObject
import java.io.ByteArrayInputStream

class MainActivity : AppCompatActivity() {
    private lateinit var webView: WebView
    private lateinit var session: SessionController
    private var pendingConnectAfterVpn = false

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

        webView = WebView(this).apply {
            setBackgroundColor(Color.parseColor("#0D1113"))
        }
        setContentView(webView)

        session = SessionController.get(this) { event, payload ->
            runOnUiThread { emitToJs(event, payload) }
        }

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
                if (consoleMessage != null) {
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

    fun requestVpnPermission() {
        pendingConnectAfterVpn = true
        val intent = VpnService.prepare(this)
        if (intent != null) {
            @Suppress("DEPRECATION")
            startActivityForResult(intent, REQ_VPN)
        } else {
            retryConnect()
        }
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

    private fun retryConnect() {
        val s = session.getSettings()
        val err = session.connect(s)
        if (err != null && err != "VPN_PERMISSION_REQUIRED") {
            emitToJs(
                "session://state",
                RuntimeState(status = "error", detail = err, pid = null, endpoint = null).toJson(),
            )
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
        // NOTE (T213, not this task): the controller is a process singleton, so
        // silencing it here also silences any other live activity's events. The
        // per-activity listener registry is the fix; until then the behaviour is
        // unchanged apart from detaching this WebView's bridge.
        session.setEmitter { _, _ -> }
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
