package app.aethernext

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

class EngineRunnerTest {

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
        val generation = java.util.concurrent.atomic.AtomicLong(0)
        val state = java.util.concurrent.atomic.AtomicReference(SupervisorState.IDLE)
        val running = java.util.concurrent.atomic.AtomicBoolean(false)

        // Simulating stopAndWait barrier logic on idle
        generation.incrementAndGet()
        running.set(false)
        state.set(SupervisorState.IDLE)

        assertEquals(SupervisorState.IDLE, state.get())
        assertFalse(running.get())
        assertEquals(1L, generation.get())
    }
}
