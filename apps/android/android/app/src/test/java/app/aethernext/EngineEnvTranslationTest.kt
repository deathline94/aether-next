package app.aethernext

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The two Settings-to-engine token translators.
 *
 * [EngineRunner.noizeEnv] already refuses a profile with no engine equivalent;
 * [EngineRunner.protocolEnv] guessed "masque" for anything it did not recognise,
 * which is how a request for WARP-in-WARP became a MASQUE tunnel with nothing
 * written down. Neither had a test, so both behaviours were free to change.
 */
class EngineEnvTranslationTest {

    @Test
    fun everyProtocolTheSettingsUiOffersReachesTheEngineWithItsMeaning() {
        assertEquals("masque", EngineRunner.protocolEnv("masque", "h3"));
        assertEquals("masque", EngineRunner.protocolEnv("masque-h2", "h2"));
        assertEquals("masque", EngineRunner.protocolEnv("MASQUE-H3", "h3"));
        assertEquals("wg", EngineRunner.protocolEnv("wireguard", "h3"));
        assertEquals("wg", EngineRunner.protocolEnv(" WG ", "h3"));
        assertEquals("gool", EngineRunner.protocolEnv("gool", "h3"));
        assertEquals("gool", EngineRunner.protocolEnv("warp-in-warp", "h3"));
    }

    @Test
    fun aLegacyWarpConfigIsPassedThroughRatherThanRewritten() {
        // The desktop shell keeps `warp` representable for exactly this reason;
        // silently turning it into "masque" here would be the same substitution
        // this change removes everywhere else.
        assertEquals("warp", EngineRunner.protocolEnv("warp", "auto"));
    }

    @Test
    fun anUnknownProtocolIsRefusedAndSaysWhatItWanted() {
        for (bad in listOf("wiregrd", "proxifier", "masque-h9", "")) {
            val thrown = runCatching { EngineRunner.protocolEnv(bad, "h3") }.exceptionOrNull()
            assertTrue(bad + " must not be guessed: got " + thrown, thrown is IllegalArgumentException)
            val message = thrown!!.message.orEmpty()
            assertTrue("the refusal must name the accepted set, got: $message", message.contains("masque|"))
        }
    }

    @Test
    fun anUnknownNoiseProfileIsRefusedToo() {
        val thrown = runCatching { EngineRunner.noizeEnv("definitely-not-a-profile") }.exceptionOrNull()
        assertTrue(
            "a noise profile with no engine equivalent must not pass through",
            thrown is IllegalArgumentException,
        );
    }
}
