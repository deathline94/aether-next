package app.aethernext

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The VPN service's two JVM-testable decisions: whether the tunnel may be
 * established at all (T202/T208), and whether a background worker still owns it
 * (T227 — the cases this file used to contain asserted on a local `AtomicLong`
 * that the test itself incremented, which no edit to `AetherVpnService` could
 * ever have broken).
 */
class AetherVpnServiceTest {

    // ─── T202 / T208: loop avoidance is fail-closed ────────────────────────────

    @Test
    fun aFailingAddDisallowedApplicationPreventsEstablish() {
        var establishCalled = false
        val refusing = DisallowApplication {
            throw IllegalStateException("addDisallowedApplication: package not found")
        }

        val failure = assertThrows(LoopAvoidance.Failure::class.java) {
            TunEstablishment.establish(
                exempt = refusing,
                packages = listOf("app.aethernext"),
                openTun = { establishCalled = true; null },
            )
        }

        assertFalse(
            "establish() must not be reached when the engine cannot be excluded: " +
                "the resulting 0.0.0.0/0 tunnel carries Aether's own traffic",
            establishCalled,
        )
        assertTrue("got: ${failure.message}", failure.message!!.contains("refusing to start a tunnel"))
        assertEquals("the message names the package that could not be excluded", listOf("app.aethernext"), failure.rejectedPackages)
    }

    @Test
    fun aLoopAvoidanceFailureIsNotAnOrdinarySwallowableException() {
        // The session's error path catches `Exception`; the refusal has to be one of
        // those rather than a logged-and-forgotten warning.
        val failure = assertThrows(IllegalStateException::class.java) {
            LoopAvoidance.enforce(DisallowApplication { throw RuntimeException("netd said no") }, listOf("app.aethernext"))
        }
        assertTrue(failure is LoopAvoidance.Failure)
        assertTrue(failure.message!!.contains("netd said no"))
    }

    @Test
    fun anEmptyExclusionListIsFatalRatherThanQuietlySkipped() {
        var establishCalled = false
        assertThrows(LoopAvoidance.Failure::class.java) {
            TunEstablishment.establish(
                exempt = DisallowApplication { },
                packages = emptyList(),
                openTun = { establishCalled = true; null },
            )
        }
        assertFalse("no packages excluded means the tunnel loops onto itself", establishCalled)
    }

    @Test
    fun everyExcludedPackageIsAttemptedBeforeTheFailureIsReported() {
        val attempted = mutableListOf<String>()
        val failure = assertThrows(LoopAvoidance.Failure::class.java) {
            LoopAvoidance.enforce(
                exempt = DisallowApplication { pkg ->
                    attempted += pkg
                    if (pkg == "app.aethernext.engine") throw SecurityException("uid not shared")
                },
                packages = listOf("app.aethernext", "app.aethernext.engine"),
            )
        }
        assertEquals("both are reported, not just the first", listOf("app.aethernext", "app.aethernext.engine"), attempted)
        assertEquals(listOf("app.aethernext.engine"), failure.rejectedPackages)
    }

    @Test
    fun establishStillRunsAndReportsARefusedTunnelWhenLoopAvoidanceSucceeds() {
        val excluded = mutableListOf<String>()
        val failure = assertThrows(IllegalStateException::class.java) {
            TunEstablishment.establish(
                exempt = DisallowApplication { excluded += it },
                packages = listOf("app.aethernext"),
                openTun = { null }, // what the platform returns when it refuses the tun
            )
        }
        assertEquals(listOf("app.aethernext"), excluded)
        assertFalse("a loop-avoidance error must not be blamed for a refused tun", failure is LoopAvoidance.Failure)
        assertTrue("got: ${failure.message}", failure.message!!.contains("establish() returned null"))
    }

    // ─── T227: the generation rule, asserted against the class that applies it ──

    @Test
    fun aSupersededWorkerMayNotPublishItsResult() {
        assertFalse(AetherVpnService.ownsTunnel(gen = 1L, currentGen = 2L, stopRequested = false))
    }

    @Test
    fun theWorkerHoldingTheCurrentGenerationOwnsTheTunnel() {
        assertTrue(AetherVpnService.ownsTunnel(gen = 2L, currentGen = 2L, stopRequested = false))
    }

    @Test
    fun aStopRequestInvalidatesEvenTheCurrentWorker() {
        assertFalse(AetherVpnService.ownsTunnel(gen = 2L, currentGen = 2L, stopRequested = true))
    }

    @Test
    fun theServiceAppliesThatRuleToItsOwnGenerationCounter() {
        val service = AetherVpnService()
        assertEquals(0L, service.getVpnGeneration())
        assertTrue("the generation a fresh service would start a worker with owns it", service.ownsTunnel(0L))
        assertFalse("a worker started for a generation the service does not have does not", service.ownsTunnel(7L))
    }

    @Test
    fun revokingTheTunnelInvalidatesTheWorkerThatStartedIt() {
        val service = AetherVpnService()
        assertTrue(service.ownsTunnel(0L))
        service.onRevoke()
        assertFalse("after a revoke no worker may report establishment", service.ownsTunnel(0L))
        assertFalse("and the tun it held is gone", VpnTunnel.up)
    }

    @Test
    fun aFailedWorkerStillReportsToTheUserEvenAfterItsOwnTeardown() {
        // The generation token moves when a failure tears the tunnel down, so the
        // error report is gated on "am I the request the user last made" instead:
        // without it every establish failure — including the loop-avoidance refusal
        // above — was dropped and the session waited for a tun that never existed.
        assertFalse("nobody asked for a tunnel yet", AetherVpnService.reportsToUser(gen = 1L, latestStartGen = 0L))
        assertTrue("the newest request hears back, even after its own stopTunnel()",
            AetherVpnService.reportsToUser(gen = 1L, latestStartGen = 1L))
        assertFalse("a superseded request stays quiet",
            AetherVpnService.reportsToUser(gen = 1L, latestStartGen = 2L))
        assertFalse("and a user-requested stop silences the in-flight worker (-1 is the disarmed token)",
            AetherVpnService.reportsToUser(gen = 3L, latestStartGen = -1L))
    }
}
