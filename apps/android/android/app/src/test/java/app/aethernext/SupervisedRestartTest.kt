package app.aethernext

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * Item 6: the dead-tunnel restart actually restarts something.
 *
 * The watchdog used to schedule `restartTunnel` and then, when the callback fired up to
 * 30 s later, bail out on `if (stopRequested || tun != null) return`. A tunnel the data
 * path has just condemned is *open* — its descriptor never went away, that is what a
 * blackhole is — so the guard cancelled precisely the case it existed for, and the
 * "supervised restart" was a log line over a dead path. [restartAction] and
 * [runSupervisedRestart] are that sequence with the descriptor, the generation and the
 * user's stop supplied as data, which is what lets the whole table be driven from a JVM
 * instead of from a phone.
 */
class SupervisedRestartTest {

    @Before
    fun resetSharedTunnelState() {
        // `VpnTunnel` is process-wide and one test here reads it on purpose.
        VpnTunnel.established(false, -1)
    }

    /** The service as a restart sees it: a descriptor, a stop flag, a generation. */
    private class FakeOps(
        var tunnelOpen: Boolean,
        var stopRequested: Boolean = false,
        var gen: Long = 5L,
        /** What `stopTunnel()` does to the generation counter: advances it. */
        var advanceGenOnClose: Boolean = true,
        var establishResult: Boolean = true,
        var throwOnEstablish: Exception? = null,
        var stopDuringClose: Boolean = false,
    ) : TunnelRestartOps {
        /** Every step, in the order it happened: the ordering is the fix, so it is asserted. */
        val events = mutableListOf<String>()
        val established = mutableListOf<Pair<Int, Long>>()
        val establishedReports = mutableListOf<Long>()
        val failures = mutableListOf<Pair<Long, String>>()

        override fun tunnelOpen(): Boolean = tunnelOpen
        override fun stopRequested(): Boolean = stopRequested
        override fun generation(): Long = gen

        override fun closeTunnel() {
            events += "close"
            tunnelOpen = false
            if (advanceGenOnClose) gen += 1
            if (stopDuringClose) stopRequested = true
        }

        override fun establish(port: Int, gen: Long): Boolean {
            events += "establish:$port@$gen"
            throwOnEstablish?.let { throw it }
            established.add(port to gen)
            return establishResult
        }

        override fun reportEstablished(gen: Long) {
            events += "reportEstablished:$gen"
            establishedReports.add(gen)
        }

        override fun reportFailed(gen: Long, reason: String) {
            events += "reportFailed:$gen"
            failures.add(gen to reason)
        }
    }

    // ─── the decision a fired callback applies ────────────────────────────────

    @Test
    fun aDeadTunnelWithItsDescriptorStillOpenIsClosedAndReplaced() {
        // THE case the early return swallowed: verdict DEAD, `tun != null`, which is the
        // normal shape of a blackholing tunnel. The old guard answered "cancel" here.
        assertEquals(
            RestartAction.ReplaceTunnel,
            restartAction(tunnelOpen = true, stopRequested = false, armedGen = 5L, currentGen = 5L),
        )
    }

    @Test
    fun anExplicitUserStopCancelsTheRestart() {
        assertEquals(
            RestartAction.Cancelled,
            restartAction(tunnelOpen = true, stopRequested = true, armedGen = 5L, currentGen = 5L),
        )
        assertEquals(
            "a stop cancels a restart even when the tunnel already came down",
            RestartAction.Cancelled,
            restartAction(tunnelOpen = false, stopRequested = true, armedGen = 5L, currentGen = 5L),
        )
    }

    @Test
    fun aCallbackArmedAgainstAnOldGenerationIsStale() {
        // Anything moved the session on — a stop, a revoke, a fresh Connect — and a late
        // callback must not build a tunnel for a session that has already gone.
        assertEquals(
            RestartAction.Cancelled,
            restartAction(tunnelOpen = true, stopRequested = false, armedGen = 5L, currentGen = 6L),
        )
        assertEquals(
            "a generation that went backwards is just as stale",
            RestartAction.Cancelled,
            restartAction(tunnelOpen = true, stopRequested = false, armedGen = 7L, currentGen = 6L),
        )
    }

    @Test
    fun aTunnelThatAlreadyWentAwayIsRebuiltWithoutAClose() {
        assertEquals(
            RestartAction.EstablishFresh,
            restartAction(tunnelOpen = false, stopRequested = false, armedGen = 5L, currentGen = 5L),
        )
    }

    // ─── the sequence the decision drives ─────────────────────────────────────

    @Test
    fun theDeadDescriptorIsClosedBeforeTheReplacementIsEstablished() {
        val ops = FakeOps(tunnelOpen = true, gen = 5L)
        assertEquals(
            RestartOutcome.Replaced,
            runSupervisedRestart(armedGen = 5L, port = 1819, ops = ops),
        )
        assertEquals(
            "close, then establish, then report — in that order",
            listOf("close", "establish:1819@6", "reportEstablished:6"),
            ops.events,
        )
        assertTrue(ops.failures.isEmpty())
    }

    @Test
    fun theReplacementIsEstablishedUnderTheGenerationCurrentAfterTheClose() {
        // `stopTunnel()` advances the generation as it tears the dead one down, so the
        // token that owns the new tunnel has to be read *after* the close: arming with
        // the pre-close number would leave the replacement owned by nobody, which is
        // what made the old code's `onVpnEstablished()` gate unreachable.
        val ops = FakeOps(tunnelOpen = true, gen = 11L)
        runSupervisedRestart(armedGen = 11L, port = 1819, ops = ops)
        assertEquals(12L, ops.established.single().second)
        assertEquals(
            "and the report is gated on the generation that owns the tun",
            12L,
            ops.establishedReports.single(),
        )
    }

    @Test
    fun aStopThatArrivesWhileTheDeadFdIsClosingStopsTheRestart() {
        val ops = FakeOps(tunnelOpen = true, gen = 5L, stopDuringClose = true)
        assertEquals(
            RestartOutcome.CancelledWhileClosing,
            runSupervisedRestart(armedGen = 5L, port = 1819, ops = ops),
        )
        assertEquals(
            "the dead tunnel was still closed, but nothing is opened for a session the user ended",
            listOf("close"),
            ops.events,
        )
    }

    @Test
    fun aStaleCallbackTouchesNothing() {
        val ops = FakeOps(tunnelOpen = true, gen = 9L)
        assertEquals(
            RestartOutcome.Cancelled,
            runSupervisedRestart(armedGen = 5L, port = 1819, ops = ops),
        )
        assertTrue("no close, no establish, no report", ops.events.isEmpty())
    }

    @Test
    fun anAlreadyClosedTunnelIsRebuiltAndReportedWithoutAClose() {
        val ops = FakeOps(tunnelOpen = false, gen = 4L)
        assertEquals(
            RestartOutcome.EstablishedFresh,
            runSupervisedRestart(armedGen = 4L, port = 1819, ops = ops),
        )
        assertEquals(listOf("establish:1819@4", "reportEstablished:4"), ops.events)
    }

    @Test
    fun aRestartThatCannotReEstablishTellsTheUserRatherThanGoingQuiet() {
        val refused = FakeOps(tunnelOpen = true, gen = 5L, establishResult = false)
        assertEquals(
            RestartOutcome.Failed,
            runSupervisedRestart(armedGen = 5L, port = 1819, ops = refused),
        )
        assertEquals(6L to RECONNECT_REQUIRED, refused.failures.single())

        val thrown = FakeOps(
            tunnelOpen = true,
            gen = 5L,
            throwOnEstablish = IllegalStateException("addDisallowedApplication failed"),
        )
        assertEquals(RestartOutcome.Failed, runSupervisedRestart(armedGen = 5L, port = 1819, ops = thrown))
        assertTrue(
            "the reason survives rather than being flattened into the generic one",
            thrown.failures.single().second.contains("addDisallowedApplication failed"),
        )
    }

    @Test
    fun thePortOfTheDeadSessionIsThePortTheReplacementIsPointedAt() {
        // Never re-read from settings: see the note in `AetherVpnService.restartTunnel`.
        val ops = FakeOps(tunnelOpen = true, gen = 1L)
        runSupervisedRestart(armedGen = 1L, port = 1900, ops = ops)
        assertEquals(1900, ops.established.single().first)
    }

    // ─── the seam the service supplies ────────────────────────────────────────

    @Test
    fun theServiceAnswersWithItsOwnDescriptorRatherThanALaggingFlag() {
        val ops = AetherVpnService().restartOps()
        assertFalse("a fresh service holds no tun", ops.tunnelOpen())
        assertFalse("and no stop has been requested", ops.stopRequested())
        // The witness has to be the descriptor the service owns: `VpnTunnel.up` is a
        // process-wide flag a non-blocking revoke clears *before* the fd is closed, and
        // a restart that read it would believe there was nothing to close over a tun
        // that was still open — the same lie in the opposite direction.
        VpnTunnel.established(true, 1819)
        assertFalse("VpnTunnel is not the source of the answer", ops.tunnelOpen())
        assertEquals(
            RestartAction.EstablishFresh,
            restartAction(ops.tunnelOpen(), ops.stopRequested(), ops.generation(), ops.generation()),
        )
    }
}
