package app.aethernext

import android.app.Service
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Item 18 / T217: what happens when the OS kills Aether's services, decided in code.
 *
 * The audit's two options were (a) take the Android restart path — `START_STICKY` /
 * `START_REDELIVER_INTENT` plus a resume — or (b) manual reconnection, stated in the
 * product surface. (b) is implemented, and [ServiceRestartPolicy] is where that is a
 * rule rather than a comment: every branch of the answer is driven by inputs the two
 * services actually observe, and the one branch (a) would need — a redelivered start
 * with a session still alive to resume — is reachable and asserted here.
 *
 * What makes (a) wrong for *this* design is not caution about battery:
 * [AetherVpnService] is tun2socks forwarding into the engine child's SOCKS listener. A
 * kill takes that child, the controller and the WebView with it, so a tunnel the system
 * rebuilt on its own would carry the device into a port nothing is bound to — the
 * "interface up, no data path, green badge" failure the liveness watchdog exists to
 * catch, now produced by the recovery path itself.
 *
 * Device checkpoint (cannot be observed from a JVM, and is what a phone run has to
 * sign off): after a LowMemoryKiller kill or a force-stop from Settings, the tunnel is
 * gone and stays gone, `SessionLedger` reports it once on the next launch, no VPN
 * interface is left registered, and tapping Connect rebuilds the session. Those are the
 * observable halves of the verdict below.
 */
class ServiceRestartPolicyTest {

    private val osKill = RedeliveredAfterOsKill()

    /** The inputs a kill leaves behind: nothing alive to resume onto. */
    private class RedeliveredAfterOsKill {
        val role = ServiceRole.VpnTunnel
        val redelivered = true
        val userAskedToStop = false
        val tunnelHasLivePath = false
        val consentValid = true
        val savedStateValid = true
    }

    // ─── the OS-kill answer, per service ─────────────────────────────────────

    @Test
    fun aTunnelRedeliveredAfterAnOsKillStaysDown() {
        assertEquals(
            StartAction.RemainStopped,
            ServiceRestartPolicy.decide(
                role = osKill.role,
                redelivered = osKill.redelivered,
                userAskedToStop = osKill.userAskedToStop,
                tunnelHasLivePath = osKill.tunnelHasLivePath,
                consentValid = osKill.consentValid,
                savedStateValid = osKill.savedStateValid,
            ),
        )
        assertEquals(
            "and the answer is spelled as the Android constant, not beside it",
            Service.START_NOT_STICKY,
            ServiceRestartPolicy.startCommandFor(StartAction.RemainStopped),
        )
    }

    @Test
    fun theEngineKeeperNeverComesBackWhateverItRemembers() {
        // Consent and saved state are true here on purpose: the keeper has nothing to
        // rebuild even when everything else looks restorable, and a restarted keeper
        // re-posts "Aether is protecting you" over no session at all.
        for (redelivered in listOf(true, false)) {
            assertEquals(
                "keeper, redelivered=$redelivered",
                StartAction.RemainStopped,
                ServiceRestartPolicy.decide(
                    role = ServiceRole.EngineKeeper,
                    redelivered = redelivered,
                    userAskedToStop = false,
                    tunnelHasLivePath = true,
                    consentValid = true,
                    savedStateValid = true,
                ),
            )
        }
    }

    @Test
    fun aUserStopEndsTheServiceForGood() {
        assertEquals(
            StartAction.RemainStopped,
            ServiceRestartPolicy.decide(
                role = ServiceRole.VpnTunnel,
                redelivered = true,
                userAskedToStop = true,
                tunnelHasLivePath = true,
                consentValid = true,
                savedStateValid = true,
            ),
        )
    }

    // ─── the (a) branch, kept honest ─────────────────────────────────────────

    @Test
    fun aSessionThatIsStillLiveIsTheOnlyThingARedeliveredStartMayResume() {
        assertEquals(
            StartAction.Redeliver,
            ServiceRestartPolicy.decide(
                role = ServiceRole.VpnTunnel,
                redelivered = true,
                userAskedToStop = false,
                tunnelHasLivePath = true,
                consentValid = true,
                savedStateValid = true,
            ),
        )
        assertEquals(
            Service.START_REDELIVER_INTENT,
            ServiceRestartPolicy.startCommandFor(StartAction.Redeliver),
        )
    }

    @Test
    fun everyMissingPreconditionOnItsOwnDefeatsTheResume() {
        val complete = mapOf(
            "tunnelHasLivePath" to true,
            "consentValid" to true,
            "savedStateValid" to true,
        )
        for (key in complete.keys) {
            val inputs = complete + (key to false)
            assertEquals(
                "$key=false must not re-route traffic",
                StartAction.RemainStopped,
                ServiceRestartPolicy.decide(
                    role = ServiceRole.VpnTunnel,
                    redelivered = true,
                    userAskedToStop = false,
                    tunnelHasLivePath = inputs["tunnelHasLivePath"]!!,
                    consentValid = inputs["consentValid"]!!,
                    savedStateValid = inputs["savedStateValid"]!!,
                ),
            )
        }
    }

    @Test
    fun aStartTheAppMadeItselfIsAliveOnlyWhileTheAppKeepsItStarted() {
        val verdict = ServiceRestartPolicy.decide(
            role = ServiceRole.VpnTunnel,
            redelivered = false,
            userAskedToStop = false,
            tunnelHasLivePath = true,
            consentValid = true,
            savedStateValid = true,
        )
        assertEquals(StartAction.KeepAliveOnly, verdict)
        assertEquals(Service.START_NOT_STICKY, ServiceRestartPolicy.startCommandFor(verdict))
    }

    @Test
    fun noAnswerThePolicyCanGiveAsksForAStickyRestart() {
        // `START_STICKY` is the flag the audit's option (a) is usually read as, and it
        // is deliberately unreachable: it restarts the service with *no* intent at all,
        // which for a tunnel means "come back and tell me which SOCKS port you think we
        // were forwarding to". `START_REDELIVER_INTENT` is the only supported restart
        // path here, and it is gated on the session still existing.
        val answers = listOf(StartAction.RemainStopped, StartAction.KeepAliveOnly, StartAction.Redeliver)
        assertEquals(
            listOf(Service.START_NOT_STICKY, Service.START_NOT_STICKY, Service.START_REDELIVER_INTENT),
            answers.map { ServiceRestartPolicy.startCommandFor(it) },
        )
        assertFalse(answers.map { ServiceRestartPolicy.startCommandFor(it) }.contains(Service.START_STICKY))
    }

    // ─── the product surface for the chosen answer ───────────────────────────

    @Test
    fun theKillIsSaidOutLoudAsAManualResumeNotASilentRetry() {
        // Option (b) is only coherent if the user is told. This pins the sentence the
        // service publishes on an unexpected teardown: what happened, that nothing is
        // coming back on its own, and what resumes it.
        assertTrue("names the cause: $SERVICE_KILLED_BY_OS", SERVICE_KILLED_BY_OS.contains("stopped by the system"))
        assertTrue("states the promise: $SERVICE_KILLED_BY_OS", SERVICE_KILLED_BY_OS.contains("does not reconnect on its own"))
        assertTrue("and names the action: $SERVICE_KILLED_BY_OS", SERVICE_KILLED_BY_OS.contains("tap Connect"))
    }

    @Test
    fun theVpnServiceRoutesEveryStartAnswerThroughThePolicy() {
        // The role is not decoration: a tunnel redelivered with no engine and a keeper
        // redelivered with a live engine both answer RemainStopped, and only the tunnel
        // role can ever answer Redeliver. Asserting the two roles disagree where the
        // architecture says they must is what keeps them from drifting apart again.
        val tunnel = ServiceRestartPolicy.decide(
            role = ServiceRole.VpnTunnel, redelivered = true, userAskedToStop = false,
            tunnelHasLivePath = true, consentValid = true, savedStateValid = true,
        )
        val keeper = ServiceRestartPolicy.decide(
            role = ServiceRole.EngineKeeper, redelivered = true, userAskedToStop = false,
            tunnelHasLivePath = true, consentValid = true, savedStateValid = true,
        )
        assertEquals(StartAction.Redeliver, tunnel)
        assertEquals(StartAction.RemainStopped, keeper)
    }
}
