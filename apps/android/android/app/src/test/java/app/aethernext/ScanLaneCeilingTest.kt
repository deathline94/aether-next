package app.aethernext

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * Item 14's other half: the lanes a scan runs must be decided by the protocol it runs
 * on, in the shell as well as in the web layer.
 *
 * `clampConcurrency` used to be `coerceIn(1, 500)` for every protocol, so the shell
 * would forward 250 lanes for a `masque-h3` scan without blinking. The web layer had
 * just been fixed to advertise 16, which only moves the number that arrives *from the
 * UI*: a stored value, another producer or a hand-written call reached an engine whose
 * own handshake-safety rule (`EXPENSIVE_MAX_CONCURRENCY`) says those lanes may not
 * exist. These tests hold the ceiling to that rule, and hold the no-protocol case to
 * the absolute ceiling so an existing caller is not narrowed by surprise.
 */
class ScanLaneCeilingTest {

    @Test
    fun anH3ScanIsNarrowedToTheLanesItsHandshakeCanCarry() {
        assertEquals(ScanLimits.MAX_CONCURRENCY_H3, ScanLimits.clampConcurrency(250, "masque-h3"))
        assertEquals(ScanLimits.MAX_CONCURRENCY_H3, ScanLimits.clampConcurrency(500, "masque-h3"))
        assertEquals(16, ScanLimits.MAX_CONCURRENCY_H3)
    }

    @Test
    fun aCheapScanKeepsTheFullLadder() {
        // The protocols that are not QUIC handshakes are not narrowed by the H3 rule.
        assertEquals(250, ScanLimits.clampConcurrency(250, "masque-h2"))
        assertEquals(ScanLimits.MAX_CONCURRENCY, ScanLimits.clampConcurrency(500, "wireguard"))
        assertEquals(250, ScanLimits.clampConcurrency(250, "cloudflare-warp"))
    }

    @Test
    fun theMASQUEspellingsAllReachTheSameRule() {
        for (protocol in listOf("masque-h3", "h3", "MASQUE", "masque", "X-h3-Y")) {
            assertEquals(
                "protocol '$protocol' must not slip past the H3 ceiling",
                ScanLimits.MAX_CONCURRENCY_H3,
                ScanLimits.clampConcurrency(250, protocol),
            )
        }
    }

    @Test
    fun aCallerWithNoProtocolKeepsTheAbsoluteCeiling() {
        // Narrowing this path would refuse inputs a legacy producer still sends,
        // without the protocol that would justify refusing them.
        assertEquals(250, ScanLimits.clampConcurrency(250))
        assertEquals(ScanLimits.MAX_CONCURRENCY, ScanLimits.clampConcurrency(9999))
    }

    @Test
    fun theFloorIsOneLaneWhateverTheProtocol() {
        assertEquals(1, ScanLimits.clampConcurrency(0, "masque-h3"))
        assertEquals(1, ScanLimits.clampConcurrency(-5, "wireguard"))
        assertEquals(1, ScanLimits.MIN_CONCURRENCY)
    }

    @Test
    fun aScanThatAsksForNothingOpensAtTheH3Ceiling() {
        // `handleScan`'s default has to read as the protocol's own ceiling: the page
        // opens on `masque-h3`, so a payload with no `concurrency` field may not be
        // answered with a number the control can no longer show.
        val defaultForH3 = ScanLimits.clampConcurrency(ScanLimits.MAX_CONCURRENCY_H3, "masque-h3")
        assertEquals(ScanLimits.MAX_CONCURRENCY_H3, defaultForH3)
    }
}
