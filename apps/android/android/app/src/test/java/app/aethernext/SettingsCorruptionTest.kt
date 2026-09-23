package app.aethernext

import android.content.Context
import android.content.ContextWrapper
import android.content.SharedPreferences
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test
import java.io.File

/**
 * Item 10: a settings blob that cannot be read is a fact to report, not a blank slate.
 *
 * `readRaw()` used to catch *every* exception and answer `Settings()`. Two writes then
 * destroyed the user's file behind that answer: the 1.0.2 one-shot in `load()` re-emitted
 * the defaults it had just invented, and any later `save()` — including the one `connect()`
 * performs before it starts — replaced the bytes outright. What the user saw was their
 * configuration reverting after a parse error nothing had told them about.
 *
 * These drive the store over fake `SharedPreferences`, because both the bug and the fix
 * live in what is on disk after the read: MISSING, Healthy and Corrupt are three answers,
 * the corrupt bytes survive, and nothing overwrites them until the user resets or the blob
 * reads again.
 */
class SettingsCorruptionTest {

    private class SettingsContext(private val baseDir: File) : ContextWrapper(null) {
        val prefs = FakeSharedPreferences()
        override fun getApplicationContext(): Context = this
        override fun getFilesDir(): File = baseDir
        override fun getSharedPreferences(name: String?, mode: Int): SharedPreferences = prefs
    }

    private lateinit var dir: File
    private lateinit var context: SettingsContext

    @Before
    fun setUp() {
        dir = File(System.getProperty("java.io.tmpdir"), "settings_corrupt_${System.nanoTime()}").apply { mkdirs() }
        context = SettingsContext(dir)
        // `SettingsHealth` is process-wide, like the report surface it feeds.
        SettingsHealth.reset()
    }

    @After
    fun tearDown() {
        SettingsHealth.reset()
        dir.deleteRecursively()
    }

    private fun stored(): String? = context.prefs.map[SettingsStore.KEY_BLOB] as? String
    private fun quarantined(): String? = context.prefs.map[SettingsStore.KEY_CORRUPT_RAW] as? String

    // ─── (a) malformed JSON ───────────────────────────────────────────────────

    @Test
    fun malformedJsonIsReportedCorruptAndLeftIntact() {
        val raw = """{"protocol":"masque","socksPort":1819,"noizeJc":"""
        context.prefs.map[SettingsStore.KEY_BLOB] = raw

        val store = SettingsStore(context)
        val settings = store.load()

        assertEquals(SettingsReadState.Corrupt, store.readState())
        assertEquals("defaults are handed over so the app still runs", "tun", settings.routingMode)
        assertEquals(
            "the corrupt bytes are the user's, and they stay where they are",
            raw,
            stored(),
        )
        assertTrue(store.hasUnresolvedCorruption())
        assertNotNull(
            "and the reason is kept, not just the fact",
            context.prefs.map[SettingsStore.KEY_CORRUPT_REASON],
        )
        assertTrue(
            "no setting is to blame when the blob itself cannot be parsed",
            SettingsHealth.snapshot()!!.isNull("field"),
        )
    }

    @Test
    fun aCorruptReadIsNotTheSameAnswerAsNothingStored() {
        val fresh = SettingsStore(context)
        fresh.load()
        assertEquals("a fresh install must not be reported as a lost file", SettingsReadState.Missing, fresh.readState())

        context.prefs.map[SettingsStore.KEY_BLOB] = "}}not json{{"
        val broken = SettingsStore(context)
        broken.load()
        assertEquals(SettingsReadState.Corrupt, broken.readState())
    }

    @Test
    fun aCorruptBlobSurvivesTheOneShotMigrationThatUsedToRewriteIt() {
        val raw = "{\"routingMode\":"
        context.prefs.map[SettingsStore.KEY_BLOB] = raw
        SettingsStore(context).load()

        assertEquals("the migration's rewrite is exactly what deleted the file", raw, stored())
        assertFalse(
            "and the one-shot stays pending rather than recording itself applied over bytes it never read",
            context.prefs.map.containsKey(SettingsStore.KEY_DEFAULTS_V102),
        )
    }

    // ─── (b) valid JSON, invalid fields ──────────────────────────────────────

    @Test
    fun aValidObjectWithFieldsNobodyCouldHaveSetIsCorruptAndLeftIntact() {
        // The interesting case `opt*` reading made invisible: valid JSON, no exception,
        // and a `Settings` full of invented values a later save would have made final.
        val raw = """{"protocol":"openvpn","socksPort":1819,"httpPort":1820}"""
        context.prefs.map[SettingsStore.KEY_BLOB] = raw

        val store = SettingsStore(context)
        store.load()

        assertEquals(SettingsReadState.Corrupt, store.readState())
        assertEquals(raw, stored())
        assertTrue(store.hasUnresolvedCorruption())
        assertEquals("protocol", SettingsHealth.snapshot()!!.optString("field"))
    }

    @Test
    fun anOutOfRangePortIsNamedRatherThanSilentlyCorrected() {
        val raw = """{"protocol":"masque","socksPort":80,"httpPort":1820}"""
        context.prefs.map[SettingsStore.KEY_BLOB] = raw
        val store = SettingsStore(context)
        store.load()

        assertEquals(SettingsReadState.Corrupt, store.readState())
        assertEquals(raw, stored())
        val report = SettingsHealth.snapshot()!!
        assertEquals("socksPort", report.optString("field"))
        assertTrue(
            "the reason quotes the value the user has to fix: $report",
            report.optString("reason").contains("80"),
        )
    }

    @Test
    fun aNumberStoredAsAStringStillReadsBecauseThatIsWhatJsonCoercionMeans() {
        // Distinct from nonsense: `optInt` coerces "1819". Pinning it keeps the new
        // strictness from turning a legacy payload into a corruption report.
        val raw = """{"protocol":"masque","socksPort":"1819","httpPort":"1820"}"""
        context.prefs.map[SettingsStore.KEY_BLOB] = raw
        val store = SettingsStore(context)
        val settings = store.load()

        assertEquals(SettingsReadState.Healthy, store.readState())
        assertEquals(1819, settings.socksPort)
        assertFalse(store.hasUnresolvedCorruption())
    }

    // ─── the write lock, and the two ways through it ──────────────────────────

    @Test
    fun aLaterSaveIsRefusedRatherThanOverwritingTheCorruptBlob() {
        val raw = """{"protocol":"""
        context.prefs.map[SettingsStore.KEY_BLOB] = raw
        val store = SettingsStore(context)
        store.load()

        try {
            store.save(Settings(protocol = "wireguard"))
            fail("a save that quietly replaces the user's unreadable file is the bug")
        } catch (e: SettingRejected) {
            assertEquals("settings", e.field)
            assertTrue("the message says what to do: ${e.message}", e.message!!.contains("Reset settings"))
        }
        assertEquals(raw, stored())
    }

    @Test
    fun everyStoreSeesTheSameRefusal() {
        // `SessionController`, `BootReceiver` and `EngineRunner` each build their own
        // store; the gate is on disk, so it cannot be walked around by picking another.
        val raw = "not json at all"
        context.prefs.map[SettingsStore.KEY_BLOB] = raw
        SettingsStore(context).load()

        try {
            SettingsStore(context).save(Settings())
            fail("a second store must not be able to overwrite it either")
        } catch (e: SettingRejected) {
            assertEquals("settings", e.field)
        }
        assertEquals(raw, stored())
    }

    @Test
    fun anExplicitResetAcceptsDefaultsAndKeepsTheRejectedBytes() {
        val raw = """{"noizeJmin":5000,"protocol":"masque"}"""
        context.prefs.map[SettingsStore.KEY_BLOB] = raw
        val store = SettingsStore(context)
        store.load()

        val defaults = store.resetCorruptSettings()

        assertEquals(SettingsReadState.Healthy, store.readState())
        assertEquals("tun", defaults.routingMode)
        assertEquals("the bytes the user may still want back stay quarantined", raw, quarantined())
        assertFalse(store.hasUnresolvedCorruption())
        store.save(Settings(protocol = "wireguard"))
        assertEquals("wireguard", SettingsStore(context).load().protocol)
        assertNull("the published report comes down with the reset", SettingsHealth.snapshot())
    }

    @Test
    fun aBlobThatReadsAgainReleasesTheLockByItself() {
        // The other way through: the file was repaired outside the app (a restore, a
        // pushed preferences file). A read that succeeds is the proof.
        context.prefs.map[SettingsStore.KEY_BLOB] = """{"protocol":"masque","transport":"""
        val store = SettingsStore(context)
        store.load()
        assertTrue(store.hasUnresolvedCorruption())

        context.prefs.map[SettingsStore.KEY_BLOB] = Settings(protocol = "gool", transport = "h3").toJson().toString()

        val after = SettingsStore(context)
        after.load()
        assertEquals(SettingsReadState.Healthy, after.readState())
        assertFalse("the write lock came off", after.hasUnresolvedCorruption())
        assertEquals("gool", SettingsStore(context).load().protocol)
        assertNull(SettingsHealth.snapshot())
    }

    @Test
    fun aFreshInstallStillPublishesItsDefaultsAndCanSave() {
        val store = SettingsStore(context)
        val settings = store.load()

        assertEquals(SettingsReadState.Missing, store.readState())
        assertNotNull("first run still lays down the one-shot payload", stored())
        assertEquals("tun", settings.routingMode)

        store.save(Settings(socksPort = 1900, httpPort = 1901))
        assertEquals(1900, SettingsStore(context).load().socksPort)
        assertFalse(store.hasUnresolvedCorruption())
    }

    // ─── the frontend contract ───────────────────────────────────────────────

    @Test
    fun theStatePayloadCarriesTheCorruption() {
        val healthy = RuntimeState().toJson()
        assertTrue(
            "`settingsError` is always present, so the UI never has to guess at a missing key",
            healthy.has("settingsError"),
        )
        assertTrue(healthy.isNull("settingsError"))

        context.prefs.map[SettingsStore.KEY_BLOB] = """{"transport":"quic"}"""
        SettingsStore(context).load()

        val error = RuntimeState(status = "error", detail = "Ready").toJson().optJSONObject("settingsError")
        assertNotNull("a corrupt read reaches the UI on the state stream", error)
        assertEquals(
            setOf("state", "reason", "field", "detectedAt", "action"),
            error!!.keys().asSequence().toSet(),
        )
        assertEquals("corrupt", error.optString("state"))
        assertEquals("reset", error.optString("action"))
        assertEquals("transport", error.optString("field"))
        assertTrue(error.optLong("detectedAt") > 0L)
    }

    @Test
    fun theQuarantinedCopyIsWhatTheResetSaysItPreserves() {
        val raw = """{"protocol":"masque","peer":12345,"noize":"unsupported_noise"}"""
        context.prefs.map[SettingsStore.KEY_BLOB] = raw
        val store = SettingsStore(context)
        store.load()
        assertEquals(raw, store.quarantinedBlob())
    }
}
