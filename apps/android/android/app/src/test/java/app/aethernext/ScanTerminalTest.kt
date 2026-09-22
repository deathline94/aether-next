package app.aethernext

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * A scan whose process died used to be reported as `scan_done` with empty fields,
 * which the webview reads as "finished, nothing found" — so the endpoints a
 * half-finished run had already surfaced were thrown away and the failure looked
 * like an empty result.
 */
class ScanTerminalTest {

    @Test
    fun aScanThatAlreadyEndedGetsNoSecondTerminalEvent() {
        assertNull(scanExitEvent(true))
    }

    @Test
    fun anAbandonedScanIsReportedAsAFailureThatKeepsResults() {
        val event = scanExitEvent(false) ?: error("the UI needs a terminal event")
        assertEquals("scan_failed", event.getString("type"))
        val message = event.getString("message")
        assertTrue("must not read as an empty success: $message", message.contains("without reporting"))
        assertTrue("partial results are kept: $message", message.contains("kept"))
        assertTrue(
            "no empty addr/rtt, which the UI used to render as 'best: ( )'",
            !event.has("addr") && !event.has("rtt"),
        )
    }

    @Test
    fun theFailurePayloadStillMatchesWhatTheWebviewTypeDeclares() {
        // apps/android/src/types.ts: { type: "scan_failed"; message: string }
        val json = JSONObject(scanExitEvent(false)!!.toString())
        assertEquals(setOf("type", "message"), json.keys().asSequence().toSet())
    }
}
