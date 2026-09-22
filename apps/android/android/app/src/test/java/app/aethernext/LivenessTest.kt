package app.aethernext

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The data-path liveness table (T203/T209).
 *
 * These verdicts are the only thing standing between a QUIC socket left bound to
 * a vanished interface and a green "connected" badge over a total blackhole, so
 * each one is driven through the tracker the service actually uses — not just the
 * pure predicate — including the streak counters and the restart budget.
 */
class LivenessTest {

    /** `[tx_packets, tx_bytes, rx_packets, rx_bytes]` as `TProxyGetStats()` returns it. */
    private fun stats(txP: Long = 0, txB: Long = 0, rxP: Long = 0, rxB: Long = 0) =
        longArrayOf(txP, txB, rxP, rxB)

    private val step = WINDOW_MS + 1

    @Test
    fun rxAdvancingWithTxFrozenIsDeathAfterThreeWindows() {
        val t = LivenessTracker()
        t.baseline(stats(), atMs = 0)

        var rx = 1L
        for (window in 1..2) {
            assertEquals(
                "window $window must still be tolerating the stall",
                LivenessDecision.Alive,
                t.onSample(stats(rxP = rx), atMs = window * step),
            )
            rx += 1
        }
        assertEquals(
            "the third consecutive frozen window is the verdict",
            LivenessDecision.DeadRxOnly,
            t.onSample(stats(rxP = rx), atMs = 3 * step),
        )
        assertTrue(LivenessDecision.DeadRxOnly.isDead)
    }

    @Test
    fun aSilentButProbingFineTunnelIsNotBounced() {
        // A device with nothing to send is silent, not dead. Without the probe gate
        // every idle phone would be torn down and rebuilt every 30 s.
        val t = LivenessTracker()
        t.baseline(stats(), atMs = 0)
        for (window in 1..8) {
            assertEquals(
                "silent window $window with no failed probe must stay alive",
                LivenessDecision.Alive,
                t.onSample(stats(), atMs = window * step),
            )
        }
        assertEquals(8, t.silentWindowCount())
    }

    @Test
    fun sixSilentWindowsWithAFailedProbeIsDeath() {
        val t = LivenessTracker()
        t.baseline(stats(), atMs = 0)
        for (window in 1..5) {
            assertEquals(
                LivenessDecision.Alive,
                t.onSample(stats(), atMs = window * step, probeFailed = true),
            )
        }
        assertEquals(
            LivenessDecision.DeadSilent,
            t.onSample(stats(), atMs = 6 * step, probeFailed = true),
        )
    }

    @Test
    fun trafficInBothDirectionsKeepsItAliveAndClearsAStall() {
        val t = LivenessTracker()
        t.baseline(stats(), atMs = 0)
        t.onSample(stats(rxP = 4), atMs = step)
        t.onSample(stats(rxP = 8), atMs = 2 * step)
        assertEquals(2, t.frozenWindowCount())

        // Two windows of rx-only stall, then the path recovers: the streak must not
        // sit around to condemn a tunnel that started working again.
        assertEquals(LivenessDecision.Alive, t.onSample(stats(txP = 1, rxP = 12), atMs = 3 * step))
        assertEquals("any window with outbound traffic clears the streak", 0, t.frozenWindowCount())
    }

    @Test
    fun aSpentBudgetIsDeathAndIsDecidedBeforeTheCounters() {
        // The ordering is the bug class: a spent budget that still reports "alive"
        // because traffic moved keeps the badge green over a tunnel that already
        // failed three supervised restarts.
        assertEquals(
            "traffic must not outrank a spent budget",
            LivenessDecision.Exhausted,
            decideLiveness(stats(), stats(txP = 5, rxP = 5), elapsedMs = step, attempt = MAX_ATTEMPTS),
        )
        assertEquals(
            "neither may a stall",
            LivenessDecision.Exhausted,
            decideLiveness(
                stats(), stats(), elapsedMs = step, attempt = MAX_ATTEMPTS,
                silentWindows = SILENT_WINDOWS, probeFailed = true,
            ),
        )
        assertTrue("a spent budget must reach the user", LivenessDecision.Exhausted.isDead)
    }

    @Test
    fun restartBudgetIsThreeAttemptsAtTwoEightAndThirtySeconds() {
        val t = LivenessTracker()
        assertEquals(RestartPlan.RetryAfter(2_000L, 1), t.consumeRestart())
        assertEquals(RestartPlan.RetryAfter(8_000L, 2), t.consumeRestart())
        assertEquals(RestartPlan.RetryAfter(30_000L, 3), t.consumeRestart())
        assertEquals(MAX_ATTEMPTS, t.attempt)
        assertEquals("the fourth verdict must not schedule another restart", RestartPlan.GiveUp, t.consumeRestart())
        assertEquals("GiveUp never spends budget", MAX_ATTEMPTS, t.attempt)

        assertEquals(2_000L, backoffFor(0))
        assertEquals(8_000L, backoffFor(1))
        assertEquals(30_000L, backoffFor(2))
        assertEquals("beyond the table it stays at the long rung", 30_000L, backoffFor(7))
    }

    @Test
    fun aNewSessionClearsStreaksButKeepsTheBudgetItWasGiven() {
        val t = LivenessTracker()
        t.baseline(stats(), atMs = 0)
        t.onSample(stats(rxP = 1), atMs = step)
        assertEquals(1, t.frozenWindowCount())

        t.reset(attempt = 2)
        assertFalse("a restarted tunnel has no baseline until the service is up again", t.hasBaseline())
        assertEquals(0, t.frozenWindowCount())
        assertEquals(0, t.silentWindowCount())
        assertEquals(2, t.attempt)
    }

    @Test
    fun theFirstSampleBecomesTheBaselineInsteadOfADeltaAgainstZero() {
        // `TProxyGetStats()` is zeroed on every tunnel entry, so a sample taken
        // before `TProxyStartService()` — or diffed against a default array — reads
        // as "no traffic" and, after six windows, kills a healthy session.
        val t = LivenessTracker()
        assertFalse(t.hasBaseline())
        assertEquals(LivenessDecision.Alive, t.onSample(stats(txP = 50, rxP = 50), atMs = 0))
        assertTrue(t.hasBaseline())
        assertEquals(
            "the adopted baseline must not itself count as a window",
            LivenessDecision.Alive,
            t.onSample(stats(txP = 50, rxP = 50), atMs = step, probeFailed = true),
        )
        assertEquals(1, t.silentWindowCount())
    }

    @Test
    fun windowsShorterThanTheCadenceDoNotCloseAWindow() {
        val t = LivenessTracker()
        t.baseline(stats(), atMs = 0)
        assertEquals(LivenessDecision.Alive, t.onSample(stats(rxP = 1), atMs = WINDOW_MS - 1))
        assertEquals("a short poll must not advance the streak", 0, t.frozenWindowCount())
        // The traffic it saw is still counted: the next window diffs against the
        // baseline, not against the discarded sample.
        assertEquals(LivenessDecision.Alive, t.onSample(stats(rxP = 1), atMs = step))
        assertEquals(1, t.frozenWindowCount())
    }

    @Test
    fun aShortArrayIsReadAsZerosRatherThanThrowing() {
        // JNI-backed stats can arrive truncated after a partial load; indexing that
        // would crash the watchdog thread, which is the one thing that reports death.
        assertEquals(
            LivenessDecision.Alive,
            decideLiveness(longArrayOf(1), longArrayOf(1), elapsedMs = step, attempt = 0),
        )
    }
}
