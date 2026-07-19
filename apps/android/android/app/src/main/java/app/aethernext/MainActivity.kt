package app.aethernext

import android.annotation.SuppressLint
import android.app.Activity
import android.content.Intent
import android.graphics.Color
import android.net.VpnService
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

    @SuppressLint("SetJavaScriptEnabled")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

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
                if (!request.isForMainFrame) {
                    return false
                }
                return request.url.scheme != "https" || request.url.host != APP_HOST
            }

            override fun shouldInterceptRequest(
                view: WebView,
                request: WebResourceRequest,
            ): android.webkit.WebResourceResponse? {
                if (request.url.scheme == "https" && request.url.host == APP_HOST) {
                    return assetLoader.shouldInterceptRequest(request.url)
                }
                // null = let system handle (or block); empty 200 half-renders pages.
                return null
            }

            override fun onPageFinished(view: WebView, url: String) {
                Log.i(TAG, "page finished: $url")
                emitToJs("session://state", session.getState().toJson())
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
        val entry = "https://appassets.androidplatform.net/assets/www/index.html"
        // Only expose bridge after client is locked to appassets host.
        webView.addJavascriptInterface(
            AetherBridge(this, session),
            "AetherAndroid",
        )
        Log.i(TAG, "loading $entry")
        webView.loadUrl(entry)
    }

    private fun showLoadError(description: String, url: String) {
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
            <p><code>$description</code></p>
            <p>url: <code>$url</code></p>
            <p>Reinstall from Latest, or check that assets/www is packaged in the APK.</p>
            </body></html>
        """.trimIndent()
        webView.loadDataWithBaseURL(null, html, "text/html", "UTF-8", null)
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
        session.setEmitter { _, _ -> }
        if (::webView.isInitialized) {
            webView.removeJavascriptInterface("AetherAndroid")
            webView.destroy()
        }
        super.onDestroy()
    }

    companion object {
        private const val TAG = "AetherMain"
        private const val REQ_VPN = 1001
        private const val APP_HOST = "appassets.androidplatform.net"
    }
}
