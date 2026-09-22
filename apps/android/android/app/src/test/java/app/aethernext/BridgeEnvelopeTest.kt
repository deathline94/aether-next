package app.aethernext

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.assertThrows
import org.junit.Test

/**
 * The envelope is the Android half of contract C-IPC-2. A rejection the UI cannot
 * classify is a rejection the UI can only print, so these assert the shape the
 * frontend reads: `error.code`, `error.message`, and `error.field` only when a
 * particular setting is the problem.
 */
class BridgeEnvelopeTest {

    @Test
    fun errorEnvelopeCarriesTheCodeAndOmitsAnAbsentField() {
        val json = JSONObject(bridgeErr("not_found", "wintun.dll is missing", null))
        assertFalse(json.getBoolean("ok"))
        val error = json.getJSONObject("error")
        assertEquals("not_found", error.getString("code"))
        assertEquals("wintun.dll is missing", error.getString("message"))
        assertFalse("an error about no field must not invent one", error.has("field"))
    }

    @Test
    fun okEnvelopeKeepsItsData() {
        val json = JSONObject(bridgeOk("hello"))
        assertTrue(json.getBoolean("ok"))
        assertEquals("hello", json.getString("data"))
    }

    @Test
    fun aRejectedSettingNamesTheFieldTheFormUses() {
        val rejected = assertThrows(SettingRejected::class.java) {
            SessionController.validateSettings(Settings().apply { scanMode = "telepathic" })
        }
        assertEquals("scanMode", rejected.field)

        val json = JSONObject(bridgeErr("validation", rejected.message ?: "", rejected.field))
        val error = json.getJSONObject("error")
        assertEquals("validation", error.getString("code"))
        assertEquals("scanMode", error.getString("field"))
    }

    @Test
    fun eachPortReportsItselfRatherThanOneMessageForBoth() {
        val http = assertThrows(SettingRejected::class.java) {
            SessionController.validateSettings(Settings().apply { httpPort = 80 })
        }
        assertEquals("httpPort", http.field)

        val socks = assertThrows(SettingRejected::class.java) {
            SessionController.validateSettings(Settings().apply { socksPort = 1 })
        }
        assertEquals("socksPort", socks.field)

        val equal = assertThrows(SettingRejected::class.java) {
            SessionController.validateSettings(Settings().apply { httpPort = socksPort })
        }
        assertEquals("httpPort", equal.field)
    }

    @Test
    fun jitterBoundsReportTheValueThatBroke() {
        val jc = assertThrows(SettingRejected::class.java) {
            SessionController.validateSettings(Settings().apply { noizeJc = -1 })
        }
        assertEquals("noizeJc", jc.field)

        val jmax = assertThrows(SettingRejected::class.java) {
            SessionController.validateSettings(
                Settings().apply { noizeJmin = 400; noizeJmax = 100 }
            )
        }
        assertEquals("noizeJmax", jmax.field)
    }

    @Test
    fun aRejectedSettingIsStillAnIllegalArgumentForExistingCallers() {
        // validateSettings has always thrown IllegalArgumentException and callers
        // catch that; the field-carrying subclass must not narrow the contract.
        assertThrows(IllegalArgumentException::class.java) {
            SessionController.validateSettings(Settings().apply { routingMode = "bridge" })
        }
    }
}
