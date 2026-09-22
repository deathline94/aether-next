package app.aethernext

import android.content.Context
import android.content.ContextWrapper
import android.content.SharedPreferences
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * T217's honest half.
 *
 * A tunnel killed from outside the app - LowMemoryKiller, force-stop, a native
 * crash - takes the `VpnService`, the engine child and the notification with it,
 * and the app learns nothing: the next launch shows STANDBY as if the user had
 * never connected. That is "unprotected, silently", which for this app is the
 * worst available outcome, and it is the reason `START_STICKY` alone is not the
 * fix: a restarted keeper would re-post "Aether is protecting you" over a tunnel
 * that is gone.
 *
 * What *is* decidable without a device is that the death leaves a trace and that
 * the trace reaches the user exactly once. Reconnecting unattended is a different
 * decision and is left to a device pass.
 */
class SessionLedgerTest {

    private class LedgerContext(private val baseDir: File) : ContextWrapper(null) {
        val prefs = FakeSharedPreferences()
        override fun getApplicationContext(): Context = this
        override fun getFilesDir(): File = baseDir
        override fun getSharedPreferences(name: String?, mode: Int): SharedPreferences = prefs
    }

    private fun withDir(block: (File) -> Unit) {
        val dir = File(System.getProperty("java.io.tmpdir"), "ledger_${System.nanoTime()}").apply { mkdirs() }
        try {
            block(dir)
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test
    fun aLiveSessionLeavesARecordAndACleanStopRemovesIt() = withDir { dir ->
        val ledger = SessionLedger(LedgerContext(dir))
        assertNull("nothing was running on a first run", ledger.takeUnfinished())

        ledger.markActive(at = 1_000L)
        assertEquals(1_000L, ledger.takeUnfinished())
        assertNull("the notice is consumed once, not re-read on every attach", ledger.takeUnfinished())

        ledger.markActive(at = 2_000L)
        ledger.clearActive()
        assertNull("a session that was stopped has nothing to report", ledger.takeUnfinished())
    }

    @Test
    fun theAgeInWordsNeverGoesNegativeOrAmbiguous() {
        assertTrue(SessionLedger.messageFor(0L, 30_000L).contains("30s"))
        assertTrue(SessionLedger.messageFor(0L, 5 * 60_000L).contains("5m"))
        val future = SessionLedger.messageFor(10_000L, 0L)
        assertTrue("a clock jump must not print a negative age: $future", future.contains("0s"))
        assertTrue(future.contains("Tunnel ended unexpectedly"))
        assertTrue(future.contains("Reconnect"))
    }

    @Test
    fun anUntornDownPreviousSessionIsReportedOnceOnTheFirstAttach() {
        val dir = File(System.getProperty("java.io.tmpdir"), "ledger_ctl_${System.nanoTime()}").apply { mkdirs() }
        try {
            val context = FakeSessionContext(dir)
            SessionLedger(context).markActive(at = System.currentTimeMillis() - 120_000L)

            val emitted = mutableListOf<Pair<String, JSONObject>>()
            val controller = SessionController(
                context = context,
                emitter = { event, payload -> emitted.add(event to payload) },
                runnerFactory = { onLine, onExit ->
                    TestableEngineRunner(
                        FakeSessionContext(dir),
                        File("fake_engine_binary"),
                        onLine,
                        onExit,
                        FakeProcessLauncher(nextProcess = FakeProcess(ProcessExitBehavior.GRACEFUL)),
                    )
                },
            )

            controller.attachUi(Any()) { _, _ -> }
            val notice = emitted.filter { it.first == "session://log" }
            assertEquals("expected exactly one notice, got: ${emitted.map { it.first }}", 1, notice.size)
            assertEquals("error", notice[0].second.optString("level"))
            assertTrue(notice[0].second.optString("message").contains("Tunnel ended unexpectedly"))

            val state = emitted.last { it.first == "session://state" }.second
            assertEquals("the status has to change too, or the notice scrolls away and STANDBY stays", "error", state.optString("status"))

            controller.attachUi(Any()) { _, _ -> }
            assertEquals("the same death must not be announced twice", 1, emitted.count { it.first == "session://log" })
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test
    fun aConnectedSessionRaisesTheRecordAndAStoppedOneTakesItBackDown() {
        val dir = File(System.getProperty("java.io.tmpdir"), "ledger_stop_${System.nanoTime()}").apply { mkdirs() }
        try {
            val context = FakeSessionContext(dir)
            var feed: (String) -> Unit = { throw IllegalStateException("no reader yet") }
            val controller = SessionController(
                context = context,
                emitter = { _, _ -> },
                runnerFactory = { onLine, onExit ->
                    feed = onLine
                    TestableEngineRunner(
                        context,
                        File("fake_engine_binary"),
                        onLine,
                        onExit,
                        FakeProcessLauncher(nextProcess = FakeProcess(ProcessExitBehavior.GRACEFUL)),
                    )
                },
            )

            assertNull(controller.connect(Settings(routingMode = "proxy-only", protocol = "masque")))
            assertNull(
                "nothing is recorded until a path is actually announced",
                SessionLedger(context).takeUnfinished(),
            )

            feed("""AETHER_EVENT {"type":"connected","detail":"proxy up"}""")
            assertNotNull(
                "a live tunnel has to be recorded, or its death cannot be noticed",
                SessionLedger(context).takeUnfinished(),
            )
            // The read above consumed it; put it back as a running session would,
            // then stop the session the way the user does.
            SessionLedger(context).markActive()
            controller.disconnect()
            assertNull(
                "a deliberate stop must not alarm the next launch",
                SessionLedger(context).takeUnfinished(),
            )
        } finally {
            dir.deleteRecursively()
        }
    }
}
