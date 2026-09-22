package app.aethernext

/**
 * The two primitives the WebView shell needs to stop handing its bridge to a page
 * it did not load (audit T219).
 *
 * Both are pure so the rules can be asserted without a device, a WebView or a
 * Robolectric harness.
 */

/**
 * HTML text escaping for anything interpolated into a generated page.
 *
 * `showLoadError` interpolates `WebResourceError.description` and the failing
 * request's URL — both attacker-influenced (any page that can make the WebView
 * fail a navigation controls the URL text) — straight into markup inside
 * `<code>` elements. A description of `<img src=x onerror=…>` was therefore live
 * script in a page that still carried the JavaScript interface. `&` and `<` are
 * enough to break out of an element; the rest is defence in depth for attribute
 * context, which the error page must never become.
 */
internal fun escapeHtml(raw: String?): String {
    if (raw.isNullOrEmpty()) return ""
    val out = StringBuilder(raw.length + 16)
    for (c in raw) {
        when (c) {
            '&' -> out.append("&amp;")
            '<' -> out.append("&lt;")
            '>' -> out.append("&gt;")
            '"' -> out.append("&quot;")
            '\'' -> out.append("&#39;")
            else -> out.append(c)
        }
    }
    return out.toString()
}

/**
 * Whether [url] is a page this APK shipped, and therefore whether the page in the
 * WebView may reach the bridge.
 *
 * The check is on the *whole* origin-and-path the shell loads, not just the host:
 * `WebViewAssetLoader` is registered at `/assets/`, and only `www/` under it is
 * ours. Anything else — `about:blank`, a `data:` URL, a redirect to another host,
 * or a sibling asset directory — is rejected.
 */
internal fun isTrustedUiUrl(url: String?, host: String, entryPrefix: String): Boolean {
    if (url.isNullOrBlank()) return false
    if (url.startsWith("about:") || url.startsWith("data:") || url.startsWith("blob:")) return false
    val lowered = url.lowercase()
    if (!lowered.startsWith("https://")) return false
    val withoutScheme = lowered.substring("https://".length)
    val pathStart = withoutScheme.indexOf('/')
    val urlHost = if (pathStart < 0) withoutScheme else withoutScheme.substring(0, pathStart)
    if (urlHost != host.lowercase()) return false
    val path = if (pathStart < 0) "/" else withoutScheme.substring(pathStart)
    return path.startsWith(entryPrefix)
}
