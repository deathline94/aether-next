package app.aethernext

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

class AppUpdaterTest {

    @Test
    fun semverPrecedenceMatchesRules() {
        assertTrue(AppUpdater.semverGt("1.3.17", "1.3.16"))
        assertTrue(AppUpdater.semverGt("v2.0.0", "1.9.9"))
        assertTrue(AppUpdater.semverGt("1.10.0", "1.9.0"))
        assertTrue(AppUpdater.semverGt("1.3.17", "1.3.17-rc.1"))
        assertFalse(AppUpdater.semverGt("1.3.16", "1.3.16"))
        assertFalse(AppUpdater.semverGt("1.3.16-beta.2", "1.3.16"))
        assertFalse(AppUpdater.semverGt("not-a-version", "1.3.16"))
    }

    @Test
    fun selectsBestAbiApkAndFallsBackToUniversal() {
        val assets = JSONArray()
            .put(
                JSONObject()
                    .put("name", "AetherNext-android-universal.apk")
                    .put("browser_download_url", "https://github.com/deathline94/aether-next/releases/download/v1.3.17/AetherNext-android-universal.apk")
                    .put("size", 24_000_000L),
            )
            .put(
                JSONObject()
                    .put("name", "AetherNext-android-arm64-v8a.apk")
                    .put("browser_download_url", "https://github.com/deathline94/aether-next/releases/download/v1.3.17/AetherNext-android-arm64-v8a.apk")
                    .put("size", 15_000_000L),
            )

        val arm64 = AppUpdater.selectAndroidAsset(assets, arrayOf("arm64-v8a", "armeabi-v7a"))
        assertEquals("AetherNext-android-arm64-v8a.apk", arm64?.name)

        assets
            .put(
                JSONObject()
                    .put("name", "AetherNext-android-armeabi-v7a.apk")
                    .put("browser_download_url", "https://github.com/deathline94/aether-next/releases/download/v1.3.17/AetherNext-android-armeabi-v7a.apk")
                    .put("size", 14_000_000L),
            )
            .put(
                JSONObject()
                    .put("name", "AetherNext-android-x86_64.apk")
                    .put("browser_download_url", "https://github.com/deathline94/aether-next/releases/download/v1.3.17/AetherNext-android-x86_64.apk")
                    .put("size", 16_000_000L),
            )

        val armv7 = AppUpdater.selectAndroidAsset(assets, arrayOf("armeabi-v7a"))
        assertEquals("AetherNext-android-armeabi-v7a.apk", armv7?.name)

        val x8664 = AppUpdater.selectAndroidAsset(assets, arrayOf("x86_64"))
        assertEquals("AetherNext-android-x86_64.apk", x8664?.name)

        val fallback = AppUpdater.selectAndroidAsset(assets, arrayOf("mips64"))
        assertEquals("AetherNext-android-universal.apk", fallback?.name)
    }

    @Test
    fun parsesSha256SumsAndRejectsBadUrlsOrFilenames() {
        val digest = "c".repeat(64)
        val body = "${"a".repeat(64)}  AetherNext-windows-x64-setup.exe\n$digest *AetherNext-android-arm64-v8a.apk\n"
        assertEquals(digest, AppUpdater.parseSha256Sums(body, "AetherNext-android-arm64-v8a.apk"))
        assertNull(AppUpdater.parseSha256Sums(body, "missing.apk"))

        assertTrue(AppUpdater.isAllowedDownloadUrl("https://objects.githubusercontent.com/releases/foo.apk"))
        assertFalse(AppUpdater.isAllowedDownloadUrl("http://github.com/foo.apk"))
        assertFalse(AppUpdater.isAllowedDownloadUrl("https://evil.example.com/foo.apk"))

        assertTrue(AppUpdater.isSafeApkName("AetherNext-android-arm64-v8a.apk"))
        assertFalse(AppUpdater.isSafeApkName("../evil.apk"))
        assertFalse(AppUpdater.isSafeApkName("bad/name.apk"))
        assertFalse(AppUpdater.isSafeApkName("installer.exe"))
    }

    @Test
    fun sha256FileHexHashesEmptyFileDeterministically() {
        val tmp = File.createTempFile("aether-updater-test-", ".bin")
        try {
            assertEquals(
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                AppUpdater.sha256FileHex(tmp),
            )
        } finally {
            tmp.delete()
        }
    }
}
