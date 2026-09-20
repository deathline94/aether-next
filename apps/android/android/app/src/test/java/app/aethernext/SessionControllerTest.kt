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
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.util.concurrent.atomic.AtomicBoolean

class FakeSessionContext(private val baseDir: File) : ContextWrapper(null) {
    val stopServiceCalls = mutableListOf<Intent?>()
    var throwOnStartForegroundService = false
    private val prefs = FakeSharedPreferences()

    override fun getFilesDir(): File = File(baseDir, "files").apply { mkdirs() }
    override fun getSharedPreferences(name: String?, mode: Int): SharedPreferences = prefs

    override fun startForegroundService(service: Intent?): ComponentName? {
        if (throwOnStartForegroundService) {
            throw SecurityException("Foreground service not allowed from background")
        }
        return ComponentName("app.aethernext", "FakeService")
    }

    override fun stopService(service: Intent?): Boolean {
        stopServiceCalls.add(service)
        return true
    }

    override fun startService(service: Intent?): ComponentName? {
        return ComponentName("app.aethernext", "FakeService")
    }
}

class SessionControllerTest {

    private val fakeBinary = File("fake_engine_binary")

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
            emit = { event, payload -> emittedEvents.add(event to payload) },
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
            emit = { _, _ -> },
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
            emit = { _, _ -> },
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
