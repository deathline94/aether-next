package app.aethernext

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.IOException
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketAddress
import java.net.SocketTimeoutException

/**
 * Item 7: silence is classified by asking the tunnel, not the radio.
 *
 * The watchdog's "probe" used to be `connectivityManager.allNetworks.none { it advertises
 * INTERNET }` — a question about the *underlying* network. A tunnel that swallows every
 * packet rides a Wi-Fi association that answers it happily, so a blackhole produced
 * `probeFailed = false`, six silent windows closed as `Alive`, and the badge stayed green
 * over a device sending traffic into nothing. These drive the replacement: a bounded
 * connect bound to the tunnel's own network, and a verdict table that keeps "genuinely
 * idle" and "cannot be measured" apart from "the tunnel is not carrying anything".
 */
class TunnelDataPathProbeTest {

    private val target = InetSocketAddress(PROBE_HOST, PROBE_PORT)

    /** A socket that records what was asked of it instead of reaching a network. */
    private class RecordingSocket(private val onConnect: (Int) -> Unit = {}) : Socket() {
        var connectTimeout: Int? = null
        var connected = false
        var closed = false

        override fun connect(endpoint: SocketAddress?, timeout: Int) {
            connectTimeout = timeout
            connected = true
            onConnect(timeout)
        }

        override fun close() {
            closed = true
        }
    }

    // ─── the verdict table ────────────────────────────────────────────────────

    @Test
    fun anAvailableNetworkAndATunnelThatAnswersNothingIsNotIdleness() {
        // The required case, and the exact pair the audit read as "idle": the network is
        // up, so the old capability probe said "nothing wrong here", while nothing the
        // device sent came back through the TUN.
        assertEquals(
            SilentPathVerdict.DeadBlackhole,
            verdictForSilentPath(underlyingAvailable = true, probe = PathProbe.Blackhole),
        )
    }

    @Test
    fun theBlackholeVerdictIsWhatTurnsSixSilentWindowsIntoADeath() {
        // Driven through the real decision function so the wiring, not just the naming,
        // is covered: the same counter snapshots that used to close as `Alive`.
        val silent = longArrayOf(0, 0, 0, 0)
        val verdict = verdictForSilentPath(underlyingAvailable = true, probe = PathProbe.Blackhole)
        assertEquals(
            LivenessDecision.DeadSilent,
            decideLiveness(
                prev = silent,
                now = silent,
                elapsedMs = WINDOW_MS + 1,
                attempt = 0,
                frozenWindows = 0,
                silentWindows = SILENT_WINDOWS - 1,
                probeFailed = verdict == SilentPathVerdict.DeadBlackhole,
            ),
        )
        assertTrue("and a dead verdict is one the service acts on", LivenessDecision.DeadSilent.isDead)

        // The old probe's answer for the same device — the radio was fine — kept this Alive.
        assertEquals(
            "a capability check alone never condemns a blackhole: this was the bug",
            LivenessDecision.Alive,
            decideLiveness(
                prev = silent, now = silent, elapsedMs = WINDOW_MS + 1, attempt = 0,
                frozenWindows = 0, silentWindows = SILENT_WINDOWS - 1,
                probeFailed = false,
            ),
        )
    }

    @Test
    fun aTunnelThatAnswersIsIdleRatherThanDead() {
        assertEquals(
            SilentPathVerdict.AliveIdle,
            verdictForSilentPath(underlyingAvailable = true, probe = PathProbe.Replied),
        )
        val silent = longArrayOf(0, 0, 0, 0)
        assertEquals(
            "an idle phone must not be bounced every 30 s",
            LivenessDecision.Alive,
            decideLiveness(
                prev = silent, now = silent, elapsedMs = WINDOW_MS + 1, attempt = 0,
                frozenWindows = 0, silentWindows = SILENT_WINDOWS,
                probeFailed = false,
            ),
        )
    }

    @Test
    fun anUnreachableDeviceIsNotTheTunnelsFault() {
        // With no underlying network at all, silence is expected and a restart cannot
        // manufacture a route. This is the case the old probe was actually good at.
        assertEquals(
            SilentPathVerdict.NotProvable,
            verdictForSilentPath(underlyingAvailable = false, probe = PathProbe.Blackhole),
        )
        assertEquals(
            SilentPathVerdict.NotProvable,
            verdictForSilentPath(underlyingAvailable = false, probe = PathProbe.Replied),
        )
    }

    @Test
    fun aPlatformThatGivesNoTunnelNetworkCannotCondemnATunnel() {
        // Below the release that exposes a readable VPN capability there is nothing to
        // bind a probe to. "Unmeasured" must not be promoted into "dead" — but it must
        // not be reported as idle either.
        assertEquals(
            SilentPathVerdict.NotProvable,
            verdictForSilentPath(underlyingAvailable = true, probe = PathProbe.Unavailable),
        )
    }

    @Test
    fun theProbeIsPaidForOncePerSilentStreakNotOncePerPoll() {
        // Silence short enough to be idleness costs nothing at all…
        for (silent in 0 until SILENT_WINDOWS - 1) {
            assertFalse("silent window $silent is not yet a verdict", shouldProbeDataPath(silent))
        }
        // …then one connect arms the verdict, and the streak is re-checked once per
        // [SILENT_WINDOWS] rather than every 5 s for as long as the phone stays quiet.
        assertTrue(shouldProbeDataPath(SILENT_WINDOWS - 1))
        for (silent in SILENT_WINDOWS until 2 * SILENT_WINDOWS - 1) {
            assertFalse("silent window $silent must not re-probe", shouldProbeDataPath(silent))
        }
        assertTrue("the second look at a long silence", shouldProbeDataPath(2 * SILENT_WINDOWS - 1))
        assertTrue(shouldProbeDataPath(3 * SILENT_WINDOWS - 1))
    }

    // ─── the bounded probe itself ────────────────────────────────────────────

    @Test
    fun aSocketThatCannotBeBoundToTheTunnelIsNeverConnected() {
        // An unbound socket from this process bypasses the TUN (loop avoidance excludes
        // our own uid), so a connect would "succeed" over the underlying network and
        // certify a dead tunnel as healthy. Refusing to probe is the only honest answer.
        val socket = RecordingSocket()
        val notes = mutableListOf<String>()
        assertEquals(
            PathProbe.Unavailable,
            probeThroughTunnel(
                bindToTunnel = { false },
                target = target,
                timeoutMs = PROBE_TIMEOUT_MS,
                newSocket = { socket },
                note = { notes += it },
            ),
        )
        assertFalse("no connect was attempted", socket.connected)
        assertTrue("and the socket was still closed", socket.closed)
        assertTrue(notes.single().contains("could not be bound"))
    }

    @Test
    fun aConnectThroughTheTunnelThatTimesOutIsABlackhole() {
        val socket = RecordingSocket { throw SocketTimeoutException("ETIMEDOUT") }
        var bound = false
        assertEquals(
            PathProbe.Blackhole,
            probeThroughTunnel(
                bindToTunnel = {
                    bound = true
                    true
                },
                target = target,
                timeoutMs = PROBE_TIMEOUT_MS,
                newSocket = { socket },
            ),
        )
        assertTrue("the socket was bound to the tunnel before it was used", bound)
        assertTrue(socket.closed)
    }

    @Test
    fun aRefusedConnectThroughTheTunnelIsInconclusive() {
        val socket = RecordingSocket { throw IOException("connection refused") }
        assertEquals(
            PathProbe.Unavailable,
            probeThroughTunnel(
                bindToTunnel = { true },
                target = target,
                timeoutMs = PROBE_TIMEOUT_MS,
                newSocket = { socket },
            ),
        )
        assertTrue(socket.closed)
    }

    @Test
    fun aConnectThatCompletesThroughTheTunnelIsAReply() {
        val socket = RecordingSocket()
        assertEquals(
            PathProbe.Replied,
            probeThroughTunnel(
                bindToTunnel = { true },
                target = target,
                timeoutMs = PROBE_TIMEOUT_MS,
                newSocket = { socket },
            ),
        )
        assertTrue(socket.connected)
        assertTrue("the probe leaves no socket behind", socket.closed)
    }

    @Test
    fun theProbeIsBoundedInTimeAndUnderOneWindow() {
        val socket = RecordingSocket()
        probeThroughTunnel(
            bindToTunnel = { true },
            target = target,
            timeoutMs = PROBE_TIMEOUT_MS,
            newSocket = { socket },
        )
        assertEquals(PROBE_TIMEOUT_MS, socket.connectTimeout)
        assertTrue(
            "a probe that outlives its window delays the next poll and any teardown queued behind it",
            PROBE_TIMEOUT_MS < WINDOW_MS.toInt(),
        )
    }

    @Test
    fun aBindingThatThrowsIsAnUnavailableProbeNotADeadTunnel() {
        // `Network.bindSocket` reports a refused bind by throwing. A binder that fails
        // for reasons of its own must not be counted as the tunnel blackholing traffic.
        val socket = RecordingSocket()
        assertEquals(
            PathProbe.Unavailable,
            probeThroughTunnel(
                bindToTunnel = { throw IOException("bind not permitted") },
                target = target,
                timeoutMs = PROBE_TIMEOUT_MS,
                newSocket = { socket },
            ),
        )
        assertFalse(socket.connected)
        assertTrue(socket.closed)
    }

    @Test
    fun aProbeTargetIsAnAddressNotAName() {
        // A hostname would put a resolver — which itself rides the tunnel — inside the
        // measurement, and add an unbounded wait to a bounded check.
        assertEquals(PROBE_HOST, target.address?.hostAddress)
        assertFalse("no DNS name in the probe target", PROBE_HOST.any { it.isLetter() })
        assertEquals(2, PROBE_TARGETS.map { it.address?.hostAddress }.distinct().size)
        assertTrue(PROBE_TARGETS.all { it.address != null && it.port == 443 })
        assertTrue(PROBE_TIMEOUT_MS * PROBE_TARGETS.size < WINDOW_MS)
    }

    @Test
    fun oneProvidersTimeoutCannotCondemnAWorkingTunnel() {
        val attempted = mutableListOf<InetSocketAddress>()
        assertEquals(PathProbe.Replied, probeIndependentTargets { target ->
            attempted += target
            if (target == PROBE_TARGETS.first()) PathProbe.Blackhole else PathProbe.Replied
        })
        assertEquals(PROBE_TARGETS, attempted)
    }

    @Test
    fun twoIndependentTimeoutsAreNeededForABlackhole() {
        val attempted = mutableListOf<InetSocketAddress>()
        assertEquals(PathProbe.Blackhole, probeIndependentTargets { target ->
            attempted += target
            PathProbe.Blackhole
        })
        assertEquals(PROBE_TARGETS, attempted)
        assertEquals(PathProbe.Unavailable, probeIndependentTargets { target ->
            if (target == PROBE_TARGETS.first()) PathProbe.Blackhole else PathProbe.Unavailable
        })
    }
}
