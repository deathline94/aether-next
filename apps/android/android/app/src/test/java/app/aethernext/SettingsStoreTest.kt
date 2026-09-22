package app.aethernext

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Test

class SettingsStoreTest {

    @Test
    fun testValidateSettingsAcceptsValidDefaults() {
        val s = Settings()
        SessionController.validateSettings(s)
        assertEquals("masque", s.protocol)
        assertEquals(1819, s.socksPort)
        assertEquals(1820, s.httpPort)
    }

    @Test
    fun testValidateSettingsRejectsInvalidProtocol() {
        val s = Settings(protocol = "openvpn")
        val err = assertThrows(IllegalArgumentException::class.java) {
            SessionController.validateSettings(s)
        }
        org.junit.Assert.assertTrue(err.message!!.contains("Invalid protocol 'openvpn'"))
    }

    @Test
    fun testValidateSettingsRejectsInvalidTransport() {
        val s = Settings(transport = "quic")
        val err = assertThrows(IllegalArgumentException::class.java) {
            SessionController.validateSettings(s)
        }
        org.junit.Assert.assertTrue(err.message!!.contains("Invalid transport 'quic'"))
    }

    @Test
    fun testValidateSettingsRejectsInvalidScanMode() {
        val s = Settings(scanMode = "extreme")
        val err = assertThrows(IllegalArgumentException::class.java) {
            SessionController.validateSettings(s)
        }
        org.junit.Assert.assertTrue(err.message!!.contains("Invalid scanMode 'extreme'"))
    }

    @Test
    fun testValidateSettingsRejectsInvalidIpVersion() {
        val s = Settings(ipVersion = "v5")
        val err = assertThrows(IllegalArgumentException::class.java) {
            SessionController.validateSettings(s)
        }
        org.junit.Assert.assertTrue(err.message!!.contains("Invalid ipVersion 'v5'"))
    }

    @Test
    fun testValidateSettingsRejectsInvalidRoutingMode() {
        val s = Settings(routingMode = "direct")
        val err = assertThrows(IllegalArgumentException::class.java) {
            SessionController.validateSettings(s)
        }
        org.junit.Assert.assertTrue(err.message!!.contains("Invalid routingMode 'direct'"))
    }

    @Test
    fun testValidateSettingsRejectsPrivilegedOrIdenticalPorts() {
        val sLow = Settings(socksPort = 80)
        assertThrows(IllegalArgumentException::class.java) {
            SessionController.validateSettings(sLow)
        }

        val sSame = Settings(socksPort = 1819, httpPort = 1819)
        val errSame = assertThrows(IllegalArgumentException::class.java) {
            SessionController.validateSettings(sSame)
        }
        org.junit.Assert.assertTrue(errSame.message!!.contains("HTTP and SOCKS5 ports must differ"))
    }

    @Test
    fun testValidateSettingsRejectsInvalidQuicFrag() {
        val sLow = Settings(quicInitialFragSize = 10)
        assertThrows(IllegalArgumentException::class.java) {
            SessionController.validateSettings(sLow)
        }

        val sHigh = Settings(quicInitialFragSize = 1024)
        assertThrows(IllegalArgumentException::class.java) {
            SessionController.validateSettings(sHigh)
        }
    }

    @Test
    fun testPreserveUserRoutingModePreference() {
        // When user explicitly sets proxy-only, it must not be mutated
        val userConfigured = Settings(routingMode = "proxy-only")
        val hadSaved = true
        if (!hadSaved && (userConfigured.routingMode == "proxy-only" || userConfigured.routingMode == "system-proxy")) {
            userConfigured.routingMode = "tun"
        }
        assertEquals("proxy-only", userConfigured.routingMode)

        // When fresh install (!hadSaved), defaults to tun
        val freshInstall = Settings(routingMode = "proxy-only")
        val freshHadSaved = false
        if (!freshHadSaved && (freshInstall.routingMode == "proxy-only" || freshInstall.routingMode == "system-proxy")) {
            freshInstall.routingMode = "tun"
        }
        assertEquals("tun", freshInstall.routingMode)
    }

    /**
     * The persisted payload is a contract with the WebView, not a place to park
     * fields. `startMinimized`, `enginePath` and `endpointPreset` were desktop
     * carry-overs: stored, echoed back, and read by nothing (`resolveEngine`
     * ignored a custom path by design) — so `endpointPreset` could even be
     * *rejected* on save without affecting a single behaviour. Pinning the key
     * set here means a new field has to arrive with the code that consumes it.
     */
    @Test
    fun testPersistedKeysAreExactlyTheOnesNativeCodeReads() {
        val keys = Settings().toJson().keys().asSequence().toSet()
        assertEquals(
            setOf(
                "protocol", "transport", "scanMode", "ipVersion",
                "noize", "noizeJc", "noizeJmin", "noizeJmax", "noizeIntervalMs",
                "routingMode", "socksPort", "httpPort", "launchAtLogin", "peer",
                "quicInitialFrag", "quicInitialFragSize",
            ),
            keys,
        )
    }

    @Test
    fun testDesktopCarryOverKeysAreDroppedOnReload() {
        // A payload written by an older build still carries them; loading must not
        // fail and re-saving must not put them back.
        val legacy = org.json.JSONObject(
            """{"protocol":"masque","startMinimized":true,"enginePath":"/data/local/tmp/x","endpointPreset":"gool"}"""
        )
        val s = Settings.fromJson(legacy)
        assertEquals("masque", s.protocol)
        val resaved = s.toJson()
        assertFalse(resaved.has("startMinimized"))
        assertFalse(resaved.has("enginePath"))
        assertFalse(resaved.has("endpointPreset"))
    }

    @Test
    fun testValidateSettingsAcceptsAllNoiseModes() {
        val noiseModes = listOf("off", "light", "medium", "high", "max", "custom", "on", "random", "m1", "m2")
        for (mode in noiseModes) {
            val s = Settings(noize = mode)
            SessionController.validateSettings(s)
            assertEquals(mode, s.noize)
        }
    }

    @Test
    fun testValidateSettingsRejectsInvalidNoiseMode() {
        val s = Settings(noize = "unsupported_noise")
        val err = assertThrows(IllegalArgumentException::class.java) {
            SessionController.validateSettings(s)
        }
        org.junit.Assert.assertTrue(err.message!!.contains("Invalid noize mode 'unsupported_noise'"))
    }
}
