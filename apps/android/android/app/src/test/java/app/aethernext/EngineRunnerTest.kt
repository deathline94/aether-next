package app.aethernext

import android.content.Context
import android.content.ContextWrapper
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

class TestableEngineRunner(
    context: Context,
    private val fakeBinary: File,
    onLine: (String) -> Unit = {},
    onExit: (Int?, Boolean) -> Unit = { _, _ -> },
    launcher: ProcessLauncher
) : EngineRunner(context, onLine, onExit, launcher) {
    override fun resolveEngine(): File = fakeBinary
    override fun configKey(): String = "a2V5" // base64("key"); no keystore in a unit test
    override fun configureProcessEnvironment(settings: Settings, binary: File): Map<String, String> {
        return mapOf("TEST_ENV" to "1")
    }
}

class EngineRunnerTest {

    private val dummyContext: Context = ContextWrapper(null)
    private val fakeBinary = File("fake_binary")

    /**
     * The key used to be handed to the engine in its environment, where it stayed
     * readable for the whole life of the process. It now goes down the control
     * pipe as the first line, and the engine refuses to start without it.
     */
    @Test
    fun testConfigKeyIsHandedOverOnStdin() {
        val fakeProc = FakeProcess(ProcessExitBehavior.UNKILLABLE)
        val launcher = FakeProcessLauncher(nextProcess = fakeProc)
        val runner = TestableEngineRunner(dummyContext, fakeBinary, launcher = launcher)

        assertNull("start should succeed with null error", runner.start(Settings()))

        val written = String(fakeProc.stdinSink.toByteArray(), Charsets.US_ASCII)
        assertTrue(
            "expected a `key <base64>` handoff line first, got: $written",
            written == "key a2V5" + String(byteArrayOf(0x0A))
        )
    }

    /**
     * T227: this case used to assert `SupervisorState.valueOf("IDLE") == IDLE`, i.e.
     * that an enum's name round-trips — nothing in `EngineRunner` could ever have
     * broken it. It now drives the runner and reads the state the runner reports.
     */
    @Test
    fun supervisorStateTracksTheRealLifecycle() {
        val runner = TestableEngineRunner(
            dummyContext, fakeBinary,
            launcher = FakeProcessLauncher(nextProcess = FakeProcess(ProcessExitBehavior.UNKILLABLE)),
        )

        assertEquals(SupervisorState.IDLE, runner.getState())

        assertNull(runner.start(Settings()))
        assertEquals("a launched engine is connecting, not connected", SupervisorState.CONNECTING, runner.getState())

        runner.setConnected()
        assertEquals("only the session's word moves it on", SupervisorState.CONNECTED, runner.getState())

        // A runner that never left IDLE must not be flung into CONNECTED by a stray
        // `setConnected()` — that is how a green badge used to survive a dead tunnel.
        val idle = TestableEngineRunner(
            dummyContext, fakeBinary,
            launcher = FakeProcessLauncher(nextProcess = FakeProcess(ProcessExitBehavior.UNKILLABLE)),
        )
        idle.setConnected()
        assertEquals(SupervisorState.IDLE, idle.getState())
    }

    @Test
    fun scanModeIsReportedByTheRunnerNotAssumed() {
        // `configureScanEnvironment` (not overridden by the test runner) reads
        // filesDir/cacheDir, so this needs the fake context rather than the bare
        // ContextWrapper the rest of the file gets away with.
        val tempDir = File(System.getProperty("java.io.tmpdir"), "scan_${System.nanoTime()}").apply { mkdirs() }
        val runner = TestableEngineRunner(
            FakeSessionContext(tempDir), fakeBinary,
            launcher = FakeProcessLauncher(nextProcess = FakeProcess(ProcessExitBehavior.UNKILLABLE)),
        )

        assertFalse("an idle runner is not a scan", runner.isScanMode())
        assertNull(runner.startScan("masque-h3", "v4", 64, 6000, "off"))
        assertTrue(runner.isScanMode())
        assertEquals("a scan reports SCANNING so connect() can interrupt it", SupervisorState.SCANNING, runner.getState())

        tempDir.deleteRecursively()
    }

    /**
     * T227: the generation token used to be a test-local `AtomicLong` the test
     * incremented itself. Read it from the runner, which is what actually decides
     * whether a finished reader thread may publish an exit.
     */
    @Test
    fun generationAdvancesWithRealStartsAndStops() {
        val runner = TestableEngineRunner(
            dummyContext, fakeBinary,
            launcher = FakeProcessLauncher(nextProcess = FakeProcess(ProcessExitBehavior.GRACEFUL)),
        )
        val before = runner.getGeneration()

        assertNull(runner.start(Settings()))
        assertTrue("start() takes a generation", runner.getGeneration() > before)
        val started = runner.getGeneration()

        assertTrue(runner.stopAndWait(1000))
        assertTrue("stop() takes another, so an in-flight reader can be recognised as stale",
            runner.getGeneration() > started)
    }

    /**
     * T227: was a local `AtomicBoolean` race between threads that shared nothing
     * with the class under test. Now sixteen threads really do call `start()` and
     * the launcher is what proves only one of them reached a `ProcessBuilder`.
     */
    @Test
    fun singleInstanceMutualExclusionUnderConcurrency() {
        val launcher = FakeProcessLauncher(nextProcess = FakeProcess(ProcessExitBehavior.UNKILLABLE))
        val runner = TestableEngineRunner(dummyContext, fakeBinary, launcher = launcher)
        val threads = 16
        val accepted = AtomicInteger(0)
        val rejected = AtomicInteger(0)
        val done = CountDownLatch(threads)

        repeat(threads) {
            Thread {
                val err = try {
                    runner.start(Settings())
                } finally {
                    done.countDown()
                }
                if (err == null) accepted.incrementAndGet() else rejected.incrementAndGet()
            }.start()
        }
        assertTrue("the contenders deadlocked", done.await(10, TimeUnit.SECONDS))

        assertEquals("exactly one launch may reach the launcher", 1, launcher.launchCount)
        assertEquals(1, accepted.get())
        assertEquals(threads - 1, rejected.get())
        assertEquals("Aether is already running", runner.start(Settings()))
    }

    @Test
    fun testStopAndWaitBarrierOnIdle() {
        val launcher = FakeProcessLauncher()
        val runner = TestableEngineRunner(dummyContext, fakeBinary, launcher = launcher)
        assertEquals(SupervisorState.IDLE, runner.getState())
        assertFalse(runner.isRunning())

        val stopped = runner.stopAndWait(1000)
        assertTrue(stopped)
        assertEquals(SupervisorState.IDLE, runner.getState())
        assertFalse(runner.isRunning())
    }

    @Test
    fun testStartAndGracefulTermination() {
        val fakeProc = FakeProcess(ProcessExitBehavior.GRACEFUL)
        val launcher = FakeProcessLauncher(nextProcess = fakeProc)
        val runner = TestableEngineRunner(dummyContext, fakeBinary, launcher = launcher)

        val err = runner.start(Settings())
        assertNull("start should succeed with null error", err)
        assertTrue(runner.isRunning())

        val stopped = runner.stopAndWait(2000)
        assertTrue("stopAndWait should return true on graceful exit", stopped)
        assertFalse(runner.isRunning())
        assertEquals(SupervisorState.IDLE, runner.getState())
    }

    @Test
    fun testStartAndForcedTermination() {
        val fakeProc = FakeProcess(ProcessExitBehavior.FORCED_ON_DESTROY_FORCIBLY)
        val launcher = FakeProcessLauncher(nextProcess = fakeProc)
        val runner = TestableEngineRunner(dummyContext, fakeBinary, launcher = launcher)

        val err = runner.start(Settings())
        assertNull(err)
        assertTrue(runner.isRunning())

        val stopped = runner.stopAndWait(2000)
        assertTrue("stopAndWait should return true when destroyForcibly kills process", stopped)
        assertTrue("destroyForcibly must have been called", fakeProc.destroyForciblyCalled.get())
        assertFalse(runner.isRunning())
        assertEquals(SupervisorState.IDLE, runner.getState())
    }

    @Test
    fun testUnkillableProcessRetainsStoppingStateAndBlocksNewLaunches() {
        val fakeProc = FakeProcess(ProcessExitBehavior.UNKILLABLE)
        val launcher = FakeProcessLauncher(nextProcess = fakeProc)
        val runner = TestableEngineRunner(dummyContext, fakeBinary, launcher = launcher)

        val err = runner.start(Settings())
        assertNull(err)
        assertTrue(runner.isRunning())

        // stopAndWait should escalate through destroy -> destroyForcibly -> fail
        val stopped = runner.stopAndWait(500)
        assertFalse("stopAndWait must return false for unkillable process", stopped)
        assertTrue("runner must remain in running state", runner.isRunning())
        assertEquals("supervisor state must remain STOPPING", SupervisorState.STOPPING, runner.getState())

        // Subsequent start attempt must be rejected
        val secondStart = runner.start(Settings())
        assertEquals("Aether is already running", secondStart)
    }
}
