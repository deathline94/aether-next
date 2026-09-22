package app.aethernext

import android.content.ComponentName
import android.content.Context
import android.content.ContextWrapper
import android.content.Intent
import android.content.SharedPreferences
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.io.File

class FakeSessionContext(private val baseDir: File) : ContextWrapper(null) {
    val stopServiceCalls = mutableListOf<Intent?>()
    val startedServices = mutableListOf<Intent?>()
    val startedForeground = mutableListOf<Intent?>()
    var throwOnStartForegroundService = false
    var throwOnStartService = false
    private val prefs = FakeSharedPreferences()

    override fun getApplicationContext(): Context = this

    override fun getFilesDir(): File = File(baseDir, "files").apply { mkdirs() }
    override fun getCacheDir(): File = File(baseDir, "cache").apply { mkdirs() }
    override fun getSharedPreferences(name: String?, mode: Int): SharedPreferences = prefs

    override fun startForegroundService(service: Intent?): ComponentName? {
        if (throwOnStartForegroundService) {
            throw SecurityException("Foreground service not allowed from background")
        }
        startedForeground.add(service)
        return ComponentName("app.aethernext", "FakeService")
    }

    override fun stopService(service: Intent?): Boolean {
        stopServiceCalls.add(service)
        return true
    }

    override fun startService(service: Intent?): ComponentName? {
        // What a backgrounded app gets back from `startService` on API 26+; this is
        // the call `stopVpnService()` used to swallow.
        if (throwOnStartService) {
            throw IllegalStateException("Not allowed to start service Intent: app is in background")
        }
        startedServices.add(service)
        return ComponentName("app.aethernext", "FakeService")
    }
}

/**
 * Session orchestration, driven through the engine's own stdout: the callbacks the
 * runner hands the line reader are the same ones the real `ProcessBuilder` child
 * feeds, so these exercise the production parsing path and not a mock of it.
 */
class SessionControllerTest {

    private val fakeBinary = File("fake_engine_binary")

    private class Harness(
        val context: FakeSessionContext,
        val controller: SessionController,
        val emitted: MutableList<Pair<String, JSONObject>>,
        val feed: (String) -> Unit,
    ) {
        fun logs(): List<String> = emitted
            .filter { it.first == "session://log" }
            .map { it.second.optString("message") }

        fun levels(): List<String> = emitted
            .filter { it.first == "session://log" }
            .map { it.second.optString("level") }

        fun scanEvents(): List<JSONObject> = emitted.filter { it.first == "scan://event" }.map { it.second }

        fun states(): List<JSONObject> = emitted.filter { it.first == "session://state" }.map { it.second }
    }

    private fun harness(routingMode: String = "proxy-only", protocol: String = "masque"): Harness {
        val tempDir = File(System.getProperty("java.io.tmpdir"), "session_${System.nanoTime()}").apply { mkdirs() }
        val fakeContext = FakeSessionContext(tempDir)
        val fakeProc = FakeProcess(ProcessExitBehavior.GRACEFUL)
        val launcher = FakeProcessLauncher(nextProcess = fakeProc)
        val emitted = mutableListOf<Pair<String, JSONObject>>()
        var feedLine: (String) -> Unit = { throw IllegalStateException("no line reader yet") }

        val controller = SessionController(
            context = fakeContext,
            emitter = { event, payload -> emitted.add(event to payload) },
            runnerFactory = { onLine, onExit ->
                feedLine = onLine
                TestableEngineRunner(fakeContext, fakeBinary, onLine, onExit, launcher)
            },
        )
        val settings = Settings(routingMode = routingMode, protocol = protocol)
        val err = controller.connect(settings)
        assertNull("connect must succeed against the fake engine, got: $err", err)
        return Harness(fakeContext, controller, emitted, { feedLine(it) })
    }

    @Before
    fun resetSharedTunnelState() {
        // VpnTunnel is process-wide state owned by the service; tests must not
        // inherit it from whichever method ran first.
        VpnTunnel.established(false, -1)
    }

    // ─── T110 / T129: structured events, fail-closed default ───────────────────

    @Test
    fun defaultStateIsDisconnectedNotInferred() {
        val tempDir = File(System.getProperty("java.io.tmpdir"), "session_default_${System.nanoTime()}").apply { mkdirs() }
        val controller = SessionController(
            context = FakeSessionContext(tempDir),
            emitter = { _, _ -> },
            runnerFactory = { onLine, onExit ->
                TestableEngineRunner(FakeSessionContext(tempDir), fakeBinary, onLine, onExit, FakeProcessLauncher())
            },
        )
        val state = controller.getState()
        assertEquals("a session that has heard nothing is disconnected", "disconnected", state.status)
        tempDir.deleteRecursively()
    }

    @Test
    fun aStreamContainingOnlyConnectedReachesConnected() {
        val h = harness(routingMode = "proxy-only")
        assertEquals("connecting", h.controller.getState().status)

        h.feed("""AETHER_EVENT {"type":"connected","detail":"proxy up"}""")

        val state = h.controller.getState()
        assertEquals("the engine's own connected event must be believed", "connected", state.status)
        assertTrue(
            "the last published state must reach the webview",
            h.states().last().optString("status") == "connected",
        )
    }

    @Test
    fun logProseSayingHandshakeSuccessfulDoesNotReachConnected() {
        val h = harness(routingMode = "proxy-only")

        // The string the deleted guard substring-matched, and the neighbouring prose
        // it also matched. None of them may move the state machine.
        h.feed("[+] handshake successful")
        h.feed("[tun] bridge active (kernel TCP / WinTUN high-throughput path)")
        h.feed("quic handshake established; alpn=h3")
        h.feed("[+] connect-ip status: 200")

        val state = h.controller.getState()
        assertEquals("prose is not a contract: state must not be inferred from it", "connecting", state.status)
        assertEquals(
            "none of those lines is an event, so none is a malformed one either",
            0,
            h.controller.malformedEventCount(),
        )
    }

    @Test
    fun proxyReadyEventAdvancesTheLocalListenersButNotTheTunnel() {
        val h = harness(routingMode = "proxy-only", protocol = "masque-h3")

        h.feed("""AETHER_EVENT {"type":"proxy_ready","socks":"127.0.0.1:1819","http":"127.0.0.1:1820"}""")

        assertEquals(
            "a MASQUE transport is not up until its tunnel reports ready",
            "connecting",
            h.controller.getState().status,
        )

        h.feed("""AETHER_EVENT {"type":"tunnel_ready","transport":"h3"}""")

        assertEquals("connected", h.controller.getState().status)
    }

    @Test
    fun aMalformedEventIsCountedAndSurfacedNotDropped() {
        val h = harness()

        h.feed("AETHER_EVENT {\"type\": \"connected\",")   // truncated JSON
        h.feed("AETHER_EVENT not json at all")
        h.feed("""AETHER_EVENT {"no_type": 1}""")

        assertEquals("three unreadable events, three counts", 3, h.controller.malformedEventCount())
        val rejected = h.logs().filter { it.contains("engine event rejected") }
        assertEquals("each one is visible on the log stream", 3, rejected.size)
        assertTrue(
            "the count is part of the message so a stream of them cannot hide",
            rejected.last().contains("#3"),
        )
        assertTrue(
            "and they are error-level, not info",
            h.levels().count { it == "error" } >= 3,
        )
        assertEquals("a malformed event still cannot claim a connection", "connecting", h.controller.getState().status)
    }

    @Test
    fun anEndpointSelectedEventSetsTheEndpointWithoutChangingStatus() {
        val h = harness()

        h.feed("""AETHER_EVENT {"type":"endpoint_selected","addr":"162.159.198.1:443","protocol":"MASQUE H3"}""")

        assertEquals("162.159.198.1:443", h.controller.getState().endpoint)
        assertEquals("connecting", h.controller.getState().status)
        assertEquals("the live scan card must be closed by the choice", "scan_done", h.scanEvents().last().optString("type"))
    }

    @Test
    fun aPublishedStateIsASnapshotAndNotASharedMutable() {
        val h = harness()
        val before = h.controller.getState()

        h.feed("""AETHER_EVENT {"type":"connected","detail":"proxy up"}""")

        val after = h.controller.getState()
        assertEquals("connecting", before.status)
        assertEquals("connected", after.status)
        assertFalse("getState() must not hand out something it later edits", before === after)
    }

    @Test
    fun aConnectedTunnelThatVanishedIsNotReportedAsConnected() {
        val h = harness(routingMode = "tun")
        h.feed("""AETHER_EVENT {"type":"proxy_ready","socks":"127.0.0.1:1819","http":"127.0.0.1:1820"}""")
        h.feed("""AETHER_EVENT {"type":"connected","detail":"quic up"}""")
        h.controller.onVpnEstablished()
        assertEquals("connected", h.controller.getState().status)

        // The service closed the fd underneath the session (process kill, revoke
        // that never reached the controller): the published status must not survive it.
        VpnTunnel.established(false, -1)

        val after = h.controller.getState()
        // Not "connecting, waiting for the tunnel": a session whose engine still
        // reports connected while the tun is gone means the device is no longer
        // routed anywhere it is being protected. That is an error the user has to
        // see, and rendering it as a transient wait is the same lie as the
        // spinner that says "saving" when nothing is pending.
        assertNotEquals("a vanished tun cannot be reported as connected", "connected", after.status)
        assertEquals("error", after.status)
        assertTrue(
            "the message must name the dropped tunnel, got: ${after.detail}",
            after.detail.contains("tunnel", ignoreCase = true) &&
                after.detail.contains("no longer routed", ignoreCase = true),
        )
        // And the one-shot must actually be revoked, so a later engine event cannot
        // re-assert the green badge over the dead path. (Whether it lands on
        // "connecting" or straight back on "error" is the recheck's business; what
        // must never happen is "connected" again while `VpnTunnel.up` is false.)
        h.feed("""AETHER_EVENT {"type":"connected","detail":"quic up"}""")
        assertNotEquals("connected", h.controller.getState().status)
    }

    // ─── T206: teardown must report what actually happened ────────────────────
    @Test
    fun disconnectReportsDisconnectedOnlyWhenTheStopWasAccepted() {
        val h = harness(routingMode = "tun")

        assertNull(h.controller.disconnect())
        assertEquals("disconnected", h.controller.getState().status)
        assertEquals("Ready", h.controller.getState().detail)
    }

    @Test
    fun disconnectSurfacesAVpnStopRefusalInsteadOfClaimingReady() {
        val h = harness(routingMode = "tun")
        VpnTunnel.established(true, 1819)
        h.context.throwOnStartService = true

        val err = h.controller.disconnect()

        assertNotNull("the refusal must reach the caller", err)
        assertTrue("got: $err", err!!.contains("VPN tunnel could not be stopped"))
        assertTrue(
            "the message says what is still up, from the service's own report",
            err.contains("the tunnel still reports itself up") && err.contains("still be carrying"),
        )
        assertEquals("error", h.controller.getState().status)
        assertEquals("the published detail is the refusal, not 'Ready'", err, h.controller.getState().detail)
        assertTrue("and it is on the log stream too", h.logs().any { it.contains("VPN tunnel could not be stopped") })
    }

    @Test
    fun aRefusedStopWithNoTunnelToReportStillSaysItCouldNotConfirm() {
        val h = harness(routingMode = "tun")
        h.context.throwOnStartService = true

        val err = h.controller.disconnect()

        assertNotNull(err)
        assertTrue("got: $err", err!!.contains("whether the tunnel closed cannot be confirmed"))
        assertEquals("error", h.controller.getState().status)
    }

    @Test
    fun aLateTunnelAckCannotReviveAnAlreadyFailedStop() {
        val h = harness(routingMode = "tun")
        VpnTunnel.established(true, 1819)
        h.context.throwOnStartService = true
        assertNotNull(h.controller.disconnect())

        // The service notices the stop later and acks. It must not paper over the
        // refused request: nothing proved the tun closed.
        h.controller.onVpnStopped()

        assertEquals("error", h.controller.getState().status)
        assertFalse("the tunnel state is what the service reports", VpnTunnel.up)
    }

    @Test
    fun aFullDeviceTunnelOnlyCountsAsConnectedOnceTheTunIsUp() {
        val h = harness(routingMode = "tun")

        h.feed("""AETHER_EVENT {"type":"proxy_ready","socks":"127.0.0.1:1819","http":"127.0.0.1:1820"}""")
        h.feed("""AETHER_EVENT {"type":"connected","detail":"quic up"}""")
        assertEquals(
            "in tun mode the engine alone cannot claim the device is routed",
            "connecting",
            h.controller.getState().status,
        )
        assertEquals(
            "the engine plus the tunnel service were both started (Intents are stubs in " +
                "a JVM unit test, so the count is the observable)",
            2,
            h.context.startedForeground.size,
        )

        h.controller.onVpnEstablished()
        assertEquals("connected", h.controller.getState().status)

        h.context.throwOnStartService = true
        val err = h.controller.disconnect()
        assertNotNull(err)
        assertEquals("error", h.controller.getState().status)
    }

    // ─── rollback (pre-existing coverage) ─────────────────────────────────────

    @Test
    fun testServiceStartFailureRollsBackCleanlyWhenEngineTerminates() {
        val tempDir = File(System.getProperty("java.io.tmpdir"), "session_ctrl_test_${System.currentTimeMillis()}").apply { mkdirs() }
        val fakeContext = FakeSessionContext(tempDir)
        fakeContext.throwOnStartForegroundService = true

        val fakeProc = FakeProcess(ProcessExitBehavior.GRACEFUL)
        val launcher = FakeProcessLauncher(nextProcess = fakeProc)

        val emittedEvents = mutableListOf<Pair<String, JSONObject>>()
        val controller = SessionController(
            context = fakeContext,
            emitter = { event, payload -> emittedEvents.add(event to payload) },
            runnerFactory = { onLine, onExit ->
                TestableEngineRunner(fakeContext, fakeBinary, onLine, onExit, launcher)
            }
        )

        val settings = Settings(routingMode = "proxy-only")
        val result = controller.connect(settings)

        assertNotNull("connect must return an error when foreground service fails", result)
        assertTrue("Error must mention service start failure", result!!.contains("Service start failed"))
        assertFalse("Engine runner must be confirmed terminated", controller.runner.isRunning())

        // Both services must have stopService called during rollback
        assertTrue("Both EngineService and AetherVpnService must be stopped", fakeContext.stopServiceCalls.size >= 2)

        val state = controller.getState()
        assertEquals("error", state.status)

        tempDir.deleteRecursively()
    }

    @Test
    fun testRollbackReportsAliveEnginePidWhenUnkillable() {
        val tempDir = File(System.getProperty("java.io.tmpdir"), "session_ctrl_unkillable_${System.currentTimeMillis()}").apply { mkdirs() }
        val fakeContext = FakeSessionContext(tempDir)
        fakeContext.throwOnStartForegroundService = true

        val unkillableProc = FakeProcess(ProcessExitBehavior.UNKILLABLE)
        val launcher = FakeProcessLauncher(nextProcess = unkillableProc)

        val controller = SessionController(
            context = fakeContext,
            emitter = { _, _ -> },
            runnerFactory = { onLine, onExit ->
                TestableEngineRunner(fakeContext, fakeBinary, onLine, onExit, launcher)
            }
        )

        val settings = Settings(routingMode = "proxy-only")
        val result = controller.connect(settings)

        assertNotNull(result)
        assertTrue("Must report that engine process is still running after timeout",
            result!!.contains("still running after rollback timeout"))
        assertTrue("Engine runner must remain in running/stopping state", controller.runner.isRunning())

        tempDir.deleteRecursively()
    }

    @Test
    fun testVpnFailureTriggersCentralizedRollback() {
        val tempDir = File(System.getProperty("java.io.tmpdir"), "session_vpn_fail_${System.currentTimeMillis()}").apply { mkdirs() }
        val fakeContext = FakeSessionContext(tempDir)

        val fakeProc = FakeProcess(ProcessExitBehavior.GRACEFUL)
        val launcher = FakeProcessLauncher(nextProcess = fakeProc)

        val controller = SessionController(
            context = fakeContext,
            emitter = { _, _ -> },
            runnerFactory = { onLine, onExit ->
                TestableEngineRunner(fakeContext, fakeBinary, onLine, onExit, launcher)
            }
        )

        // Simulate VPN failure event
        controller.onVpnFailed("tun2socks crashed")

        assertFalse("Engine runner must be stopped on VPN failure", controller.runner.isRunning())
        assertEquals("Both EngineService and AetherVpnService must be stopped", 2, fakeContext.stopServiceCalls.size)

        val state = controller.getState()
        assertEquals("error", state.status)
        assertTrue(state.detail.contains("VPN failed: tun2socks crashed"))

        tempDir.deleteRecursively()
    }
}
