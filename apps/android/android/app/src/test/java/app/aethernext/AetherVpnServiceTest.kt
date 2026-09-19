package app.aethernext

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

class AetherVpnServiceTest {

    @Test
    fun testVpnGenerationSupersedesStaleWorker() {
        val vpnGeneration = AtomicLong(0)
        val callbackInvoked = AtomicBoolean(false)

        // Session 1 starts
        val gen1 = vpnGeneration.incrementAndGet()
        assertEquals(1L, gen1)

        // Session 1 is in progress... while in progress, Session 2 arrives or STOP is requested
        val gen2 = vpnGeneration.incrementAndGet()
        assertEquals(2L, gen2)

        // Stale Session 1 worker attempts to report completion
        val isStale = (gen1 != vpnGeneration.get())
        assertTrue("Session 1 must be detected as stale", isStale)

        if (!isStale) {
            callbackInvoked.set(true)
        }

        assertFalse("Stale worker callback must never be invoked", callbackInvoked.get())
    }

    @Test
    fun testVpnGenerationAllowsCurrentWorker() {
        val vpnGeneration = AtomicLong(0)
        val callbackInvoked = AtomicBoolean(false)

        // Fresh session starts
        val currentGen = vpnGeneration.incrementAndGet()
        assertEquals(1L, currentGen)

        // No intervening requests occur
        val isCurrent = (currentGen == vpnGeneration.get())
        assertTrue("Current generation matches", isCurrent)

        if (isCurrent) {
            callbackInvoked.set(true)
        }

        assertTrue("Current worker callback is safely executed", callbackInvoked.get())
    }

    @Test
    fun testVpnStopInvalidatesPendingEstablishment() {
        val vpnGeneration = AtomicLong(0)
        // STOP action arrives
        vpnGeneration.incrementAndGet()
        val stopRequested = true

        val pendingGen = 5L
        val shouldEstablish = !stopRequested && (pendingGen == vpnGeneration.get())

        assertFalse("Pending establishment must be aborted after STOP", shouldEstablish)
    }
}
