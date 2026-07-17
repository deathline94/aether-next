package app.aethernext

import android.annotation.SuppressLint
import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.webkit.WebChromeClient
import android.webkit.WebSettings
import android.webkit.WebView
import android.webkit.WebViewClient
import androidx.appcompat.app.AppCompatActivity
import org.json.JSONObject

class MainActivity : AppCompatActivity() {
    private lateinit var webView: WebView
    private lateinit var session: SessionController
    private var pendingConnectAfterVpn = false

    @SuppressLint("SetJavaScriptEnabled")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        webView = WebView(this)
        setContentView(webView)

        session = SessionController.get(this) { event, payload ->
            runOnUiThread { emitToJs(event, payload) }
        }

        webView.settings.apply {
            javaScriptEnabled = true
            domStorageEnabled = true
            allowFileAccess = true
            allowContentAccess = true
            mixedContentMode = WebSettings.MIXED_CONTENT_ALWAYS_ALLOW
            cacheMode = WebSettings.LOAD_DEFAULT
            mediaPlaybackRequiresUserGesture = false
        }
        webView.webChromeClient = WebChromeClient()
        webView.webViewClient = object : WebViewClient() {
            override fun onPageFinished(view: WebView?, url: String?) {
                // push current state after load
                emitToJs("session://state", session.getState().toJson())
            }
        }
        webView.addJavascriptInterface(
            AetherBridge(this, session),
            "AetherAndroid",
        )
        webView.loadUrl("file:///android_asset/www/index.html")
    }

    fun requestVpnPermission() {
        pendingConnectAfterVpn = true
        val intent = VpnService.prepare(this)
        if (intent != null) {
            startActivityForResult(intent, REQ_VPN)
        } else {
            // already granted
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
        val ev = JSONObject.quote(event)
        val pl = JSONObject.quote(payload.toString())
        // payload is already JSON object string â€” pass raw object into JS
        val js =
            "window.__aetherEmit && window.__aetherEmit($ev, $pl);"
        webView.evaluateJavascript(js, null)
    }

    override fun onDestroy() {
        // Keep engine running if connected; only destroy WebView.
        webView.destroy()
        super.onDestroy()
    }

    companion object {
        private const val REQ_VPN = 1001
    }
}
