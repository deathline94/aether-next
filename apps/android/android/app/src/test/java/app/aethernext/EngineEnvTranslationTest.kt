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

    /**
     * The ladder the Settings menu shows is four rungs, and the phone must send four
     * distinct engine names for them. Both "High" and "Max" used to arrive as
     * `heavy`, which the engine's own normalize() folds to `max` — so a user who
     * picked the second-loudest setting got the loudest one, and desktop and the
     * phone disagreed about what the same choice meant.
     */
    @Test
    fun theFourNoiseRungsStayFourDistinctEngineNames() {
        val ladder = listOf("light", "medium", "high", "max").map { EngineRunner.noizeEnv(it) }
        assertEquals("off|light|medium|high|max", (listOf("off") + ladder).joinToString("|"));
        assertEquals("each rung must reach the engine as itself", 4, ladder.toSet().size);
    }

    @Test
    fun legacyProfileNamesLandOnTheRungTheEngineGivesThem() {
        // obfuscation::normalize folds aggressive|heavy into max and gfw into high;
        // a saved setting carrying an old name has to mean the same thing here.
        assertEquals("max", EngineRunner.noizeEnv("aggressive"));
        assertEquals("max", EngineRunner.noizeEnv("heavy"));
        assertEquals("high", EngineRunner.noizeEnv("gfw"));
        assertEquals("medium", EngineRunner.noizeEnv("balanced"));
        assertEquals("custom", EngineRunner.noizeEnv("custom"));
    }
}
