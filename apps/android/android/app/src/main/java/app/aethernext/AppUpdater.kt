package app.aethernext

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.SystemClock
import android.provider.Settings as AndroidSettings
import androidx.core.content.FileProvider
import okhttp3.OkHttpClient
import okhttp3.Request
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.io.FileOutputStream
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.URI
import java.security.MessageDigest
import java.util.concurrent.TimeUnit

data class AndroidAssetChoice(
    val name: String,
    val url: String,
    val size: Long,
)

/**
 * Inline GitHub Releases updater for Aether Next Android.
 *
 * Pure parsing/selection/verification helpers live in the companion object so JVM
 * unit tests exercise SemVer precedence, ABI selection, host pinning, and SHA-256
 * parsing without Android runtime mocks.
 */
class AppUpdater(
    private val baseClient: OkHttpClient = OkHttpClient(),
) {
    fun checkUpdate(
        currentVersion: String,
        httpPort: Int?,
        useLocalProxy: Boolean,
    ): JSONObject {
        val client = clientFor(httpPort, useLocalProxy, readTimeoutSecs = 20)
        val req = Request.Builder()
            .url(LATEST_RELEASE_API)
            .header("User-Agent", "AetherNext/$currentVersion")
            .header("Accept", "application/vnd.github+json")
            .get()
            .build()

        val bodyText = client.newCall(req).execute().use { resp ->
            if (!resp.isSuccessful) {
                throw Exception("Update check failed: HTTP ${resp.code}")
            }
            resp.body?.string().orEmpty()
        }

        val payload = JSONObject(bodyText)
        val tag = payload.optString("tag_name", "").trim()
        if (tag.isEmpty()) {
            throw Exception("Latest GitHub release is missing tag_name.")
        }

        val latestVersion = tag.removePrefix("v")
        val releaseUrl = sanitizeReleasePage(payload.optString("html_url", ""))
        val notes = payload.optString("body", "").trim().take(1500)
        val assets = payload.optJSONArray("assets") ?: JSONArray()
        val chosen = selectAndroidAsset(assets, Build.SUPPORTED_ABIS ?: emptyArray())
        val available = semverGt(latestVersion, currentVersion) && chosen != null

        val sha256 = if (available && chosen != null) {
            fetchExpectedSha256(client, currentVersion, assets, chosen.name)
        } else {
            null
        }

        return JSONObject()
            .put("available", available)
            .put("currentVersion", currentVersion)
            .put("latestVersion", latestVersion)
            .put("releaseUrl", releaseUrl)
            .put("assetName", chosen?.name ?: "")
            .put("assetUrl", chosen?.url ?: "")
            .put("assetSize", chosen?.size ?: 0L)
            .put("sha256", sha256 ?: JSONObject.NULL)
            .put("notes", notes)
    }

    fun downloadAndInstall(
        context: Context,
        currentVersion: String,
        assetUrl: String,
        assetName: String,
        expectedSha256: String?,
        httpPort: Int?,
        useLocalProxy: Boolean,
        onProgress: (JSONObject) -> Unit,
    ): JSONObject {
        if (!isAllowedDownloadUrl(assetUrl)) {
            throw Exception("Refusing update download from untrusted URL.")
        }
        if (!isSafeApkName(assetName)) {
            throw Exception("Refusing unsafe APK asset file name.")
        }

        val expected = expectedSha256
            ?.trim()
            ?.lowercase()
            ?.takeIf { it.length == 64 && it.all { c -> c in '0'..'9' || c in 'a'..'f' } }

        val updatesDir = File(context.cacheDir, "updates").apply { mkdirs() }
        val dest = File(updatesDir, assetName)

        // Reuse an already-downloaded verified APK (e.g. immediately after granting
        // Unknown App Sources permission) without burning bandwidth again.
        val cachedValid = dest.isFile && expected != null && sha256FileHex(dest) == expected
        if (!cachedValid) {
            onProgress(progressPayload("downloading", 0L, 0L, 0, "Connecting to GitHub Releases..."))
            val client = clientFor(httpPort, useLocalProxy, readTimeoutSecs = 60)
            val req = Request.Builder()
                .url(assetUrl)
                .header("User-Agent", "AetherNext/$currentVersion")
                .get()
                .build()

            val part = File(updatesDir, "$assetName.part")
            try {
                client.newCall(req).execute().use { resp ->
                    if (!resp.isSuccessful) {
                        throw Exception("Update download failed: HTTP ${resp.code}")
                    }
                    if (!isAllowedDownloadUrl(resp.request.url.toString())) {
                        throw Exception("Refusing update redirect to untrusted host.")
                    }
                    val body = resp.body ?: throw Exception("Empty response body.")
                    val total = body.contentLength().coerceAtLeast(0L)
                    if (total > MAX_DOWNLOAD_BYTES) {
                        throw Exception("Update APK exceeds 150 MiB safety limit.")
                    }

                    val digest = MessageDigest.getInstance("SHA-256")
                    val buf = ByteArray(64 * 1024)
                    var downloaded = 0L
                    var lastEmit = 0L

                    body.byteStream().use { input ->
                        FileOutputStream(part).use { out ->
                            while (true) {
                                val read = input.read(buf)
                                if (read <= 0) break
                                downloaded += read
                                if (downloaded > MAX_DOWNLOAD_BYTES) {
                                    throw Exception("Update stream exceeded 150 MiB safety limit.")
                                }
                                out.write(buf, 0, read)
                                digest.update(buf, 0, read)
                                val now = SystemClock.elapsedRealtime()
                                if (now - lastEmit >= 150L) {
                                    val pct = if (total > 0L) ((downloaded * 100L) / total).toInt().coerceIn(0, 100) else 0
                                    onProgress(progressPayload("downloading", downloaded, total, pct, "Downloading APK..."))
                                    lastEmit = now
                                }
                            }
                            out.fd.sync()
                        }
                    }

                    onProgress(progressPayload("verifying", downloaded, total, 100, "Verifying SHA-256 digest..."))
                    val gotHex = digest.digest().joinToString("") { "%02x".format(it) }
                    if (expected != null && gotHex != expected) {
                        throw Exception("Downloaded APK failed SHA-256 verification.")
                    }
                }
                if (dest.exists()) dest.delete()
                if (!part.renameTo(dest)) {
                    throw Exception("Could not finalize downloaded APK file.")
                }
            } catch (e: Exception) {
                part.delete()
                onProgress(progressPayload("error", 0L, 0L, 0, e.message ?: "Update download failed"))
                throw e
            }
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O && !context.packageManager.canRequestPackageInstalls()) {
            onProgress(
                progressPayload(
                    "permission_required",
                    100L,
                    100L,
                    100,
                    "Allow 'Install unknown apps' for Aether Next, then tap Install update.",
                ),
            )
            val permIntent = Intent(
                AndroidSettings.ACTION_MANAGE_UNKNOWN_APP_SOURCES,
                Uri.parse("package:${context.packageName}"),
            ).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            context.startActivity(permIntent)
            return JSONObject()
                .put("status", "permission_required")
                .put("path", dest.absolutePath)
        }

        onProgress(progressPayload("installing", 100L, 100L, 100, "Opening Android package installer..."))
        val apkUri = FileProvider.getUriForFile(context, "${context.packageName}.fileprovider", dest)
        val installIntent = Intent(Intent.ACTION_VIEW)
            .setDataAndType(apkUri, "application/vnd.android.package-archive")
            .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_ACTIVITY_NEW_TASK)
        context.startActivity(installIntent)

        return JSONObject()
            .put("status", "installing")
            .put("path", dest.absolutePath)
    }

    private fun clientFor(httpPort: Int?, useLocalProxy: Boolean, readTimeoutSecs: Long): OkHttpClient {
        val builder = baseClient.newBuilder()
            .connectTimeout(15, TimeUnit.SECONDS)
            .readTimeout(readTimeoutSecs, TimeUnit.SECONDS)
            .callTimeout(if (readTimeoutSecs > 30) 300 else 25, TimeUnit.SECONDS)
        if (useLocalProxy && httpPort != null && httpPort in 1024..65535) {
            builder.proxy(Proxy(Proxy.Type.HTTP, InetSocketAddress("127.0.0.1", httpPort)))
        }
        return builder.build()
    }

    private fun fetchExpectedSha256(
        client: OkHttpClient,
        currentVersion: String,
        assets: JSONArray,
        targetAssetName: String,
    ): String? {
        for (i in 0 until assets.length()) {
            val item = assets.optJSONObject(i) ?: continue
            if (item.optString("name") != "SHA256SUMS.txt") continue
            val sumsUrl = item.optString("browser_download_url")
            if (!isAllowedDownloadUrl(sumsUrl)) return null
            val req = Request.Builder()
                .url(sumsUrl)
                .header("User-Agent", "AetherNext/$currentVersion")
                .get()
                .build()
            return try {
                client.newCall(req).execute().use { resp ->
                    if (!resp.isSuccessful || !isAllowedDownloadUrl(resp.request.url.toString())) return null
                    parseSha256Sums(resp.body?.string().orEmpty(), targetAssetName)
                }
            } catch (_: Exception) {
                null
            }
        }
        return null
    }

    companion object {
        const val LATEST_RELEASE_API = "https://api.github.com/repos/deathline94/aether-next/releases/latest"
        const val RELEASES_PAGE = "https://github.com/deathline94/aether-next/releases"
        private const val MAX_DOWNLOAD_BYTES = 150L * 1024L * 1024L

        private val ALLOWED_HOSTS = setOf(
            "github.com",
            "objects.githubusercontent.com",
            "release-assets.githubusercontent.com",
        )

        private val HEX64_RE = Regex("^[0-9a-fA-F]{64}$")

        fun progressPayload(
            stage: String,
            downloadedBytes: Long,
            totalBytes: Long,
            percent: Int,
            message: String,
        ): JSONObject = JSONObject()
            .put("stage", stage)
            .put("downloadedBytes", downloadedBytes)
            .put("totalBytes", totalBytes)
            .put("percent", percent)
            .put("message", message)

        fun isAllowedDownloadUrl(url: String): Boolean {
            return try {
                val uri = URI(url.trim())
                uri.scheme.equals("https", ignoreCase = true) &&
                    uri.userInfo == null &&
                    uri.host?.lowercase() in ALLOWED_HOSTS
            } catch (_: Exception) {
                false
            }
        }

        fun isSafeApkName(name: String): Boolean {
            val trimmed = name.trim()
            if (trimmed.isEmpty()) return false
            if (trimmed.contains('/') || trimmed.contains('\\') || trimmed.contains("..") || trimmed.contains(':')) {
                return false
            }
            return trimmed.endsWith(".apk", ignoreCase = true)
        }

        fun sanitizeReleasePage(candidate: String?): String {
            if (candidate.isNullOrBlank()) return RELEASES_PAGE
            return try {
                val uri = URI(candidate.trim())
                if (
                    uri.scheme.equals("https", ignoreCase = true) &&
                    uri.host.equals("github.com", ignoreCase = true) &&
                    (uri.path ?: "").startsWith("/deathline94/aether-next/releases")
                ) {
                    uri.toString()
                } else {
                    RELEASES_PAGE
                }
            } catch (_: Exception) {
                RELEASES_PAGE
            }
        }

        fun parseSha256Sums(body: String, assetName: String): String? {
            for (line in body.lineSequence()) {
                val parts = line.trim().split(Regex("\\s+"), limit = 2)
                if (parts.size < 2) continue
                val digest = parts[0]
                val name = parts[1].trimStart('*').trim()
                if (name == assetName && HEX64_RE.matches(digest)) {
                    return digest.lowercase()
                }
            }
            return null
        }

        fun selectAndroidAsset(assets: JSONArray, supportedAbis: Array<String>): AndroidAssetChoice? {
            val candidates = mutableListOf<AndroidAssetChoice>()
            for (i in 0 until assets.length()) {
                val item = assets.optJSONObject(i) ?: continue
                val name = item.optString("name", "").trim()
                val url = item.optString("browser_download_url", "").trim()
                val size = item.optLong("size", 0L).coerceAtLeast(0L)
                if (name.isEmpty() || !isSafeApkName(name) || !isAllowedDownloadUrl(url)) continue
                candidates += AndroidAssetChoice(name, url, size)
            }
            for (abi in supportedAbis) {
                val expectedName = "AetherNext-android-${abi.lowercase()}.apk"
                candidates.firstOrNull { it.name.equals(expectedName, ignoreCase = true) }?.let { return it }
            }
            candidates.firstOrNull { it.name.equals("AetherNext-android-universal.apk", ignoreCase = true) }
                ?.let { return it }
            return candidates.firstOrNull()
        }

        private fun parseSemver(raw: String): Pair<LongArray, List<String>>? {
            val trimmed = raw.trim().removePrefix("v").substringBefore('+')
            if (trimmed.isEmpty()) return null
            val dash = trimmed.indexOf('-')
            val core = if (dash >= 0) trimmed.substring(0, dash) else trimmed
            val pre = if (dash >= 0) trimmed.substring(dash + 1) else ""
            val nums = core.split('.')
            if (nums.isEmpty() || nums.size > 3) return null
            val ver = LongArray(3)
            for (i in nums.indices) {
                val part = nums[i]
                if (part.isEmpty() || !part.all { it.isDigit() }) return null
                ver[i] = part.toLongOrNull() ?: return null
            }
            val preParts = if (pre.isEmpty()) emptyList() else pre.split('.')
            return ver to preParts
        }

        fun semverGt(candidate: String, current: String): Boolean {
            val (ca, cpre) = parseSemver(candidate) ?: return false
            val (cu, cupre) = parseSemver(current) ?: return false
            for (i in 0..2) {
                if (ca[i] != cu[i]) return ca[i] > cu[i]
            }
            if (cpre.isEmpty() && cupre.isEmpty()) return false
            if (cpre.isEmpty()) return true
            if (cupre.isEmpty()) return false
            for (i in 0 until minOf(cpre.size, cupre.size)) {
                val a = cpre[i]
                val b = cupre[i]
                if (a == b) continue
                val an = a.toLongOrNull()
                val bn = b.toLongOrNull()
                return when {
                    an != null && bn != null -> an > bn
                    an != null && bn == null -> false
                    an == null && bn != null -> true
                    else -> a > b
                }
            }
            return cpre.size > cupre.size
        }

        fun sha256FileHex(file: File): String? = try {
            val digest = MessageDigest.getInstance("SHA-256")
            val buf = ByteArray(64 * 1024)
            file.inputStream().use { input ->
                while (true) {
                    val n = input.read(buf)
                    if (n <= 0) break
                    digest.update(buf, 0, n)
                }
            }
            digest.digest().joinToString("") { "%02x".format(it) }
        } catch (_: Exception) {
            null
        }
    }
}
