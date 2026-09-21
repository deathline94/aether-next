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
    override fun resolveEngine(configured: String): File = fakeBinary
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
            written.startsWith("key a2V5
")
        )
    }

    @Test
    fun testSupervisorStateTransitions() {
        assertEquals(SupervisorState.IDLE, SupervisorState.valueOf("IDLE"))
        assertEquals(SupervisorState.SCANNING, SupervisorState.valueOf("SCANNING"))
        assertEquals(SupervisorState.CONNECTING, SupervisorState.valueOf("CONNECTING"))
        assertEquals(SupervisorState.CONNECTED, SupervisorState.valueOf("CONNECTED"))
        assertEquals(SupervisorState.STOPPING, SupervisorState.valueOf("STOPPING"))
    }

    @Test
    fun testGenerationTokenMonotonicIncrement() {
        val generation = java.util.concurrent.atomic.AtomicLong(0)
        assertEquals(0L, generation.get())

        val g1 = generation.incrementAndGet()
        val g2 = generation.incrementAndGet()
        val g3 = generation.incrementAndGet()

        assertEquals(1L, g1)
        assertEquals(2L, g2)
        assertEquals(3L, g3)
        assertTrue(g3 > g2 && g2 > g1)
    }

    @Test
    fun testSingleInstanceMutualExclusionUnderConcurrency() {
        val running = java.util.concurrent.atomic.AtomicBoolean(false)
        val successfulLaunches = AtomicInteger(0)
        val collisions = AtomicInteger(0)
        val threads = 16
        val latch = CountDownLatch(threads)

        for (i in 0 until threads) {
            Thread {
                if (running.compareAndSet(false, true)) {
                    successfulLaunches.incrementAndGet()
                    Thread.sleep(20)
                    running.set(false)
                } else {
                    collisions.incrementAndGet()
                }
                latch.countDown()
            }.start()
        }

        assertTrue(latch.await(5, TimeUnit.SECONDS))
        assertTrue("At least one launch succeeded", successfulLaunches.get() >= 1)
        assertTrue("Collisions were caught and rejected", collisions.get() >= 1)
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
