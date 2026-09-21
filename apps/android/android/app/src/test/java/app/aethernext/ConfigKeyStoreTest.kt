package app.aethernext

import android.content.Context
import android.content.ContextWrapper
import android.content.SharedPreferences
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test
import java.io.File
import java.io.InputStream
import java.io.OutputStream
import java.security.Key
import java.security.KeyStore
import java.security.KeyStoreSpi
import java.security.cert.Certificate
import java.util.Collections
import java.util.Date
import java.util.Enumeration
import javax.crypto.KeyGenerator

class MockKeyStoreSpi : KeyStoreSpi() {
    private val keys = mutableMapOf<String, Key>()

    override fun engineGetKey(alias: String?, password: CharArray?): Key? = keys[alias]
    override fun engineGetCertificateChain(alias: String?): Array<Certificate>? = null
    override fun engineGetCertificate(alias: String?): Certificate? = null
    override fun engineGetCreationDate(alias: String?): Date? = null
    override fun engineSetKeyEntry(alias: String?, key: Key?, password: CharArray?, chain: Array<out Certificate>?) {
        if (alias != null && key != null) keys[alias] = key
    }
    override fun engineSetKeyEntry(alias: String?, key: ByteArray?, chain: Array<out Certificate>?) {}
    override fun engineSetCertificateEntry(alias: String?, cert: Certificate?) {}
    override fun engineDeleteEntry(alias: String?) { keys.remove(alias) }
    override fun engineAliases(): Enumeration<String> = Collections.enumeration(keys.keys)
    override fun engineContainsAlias(alias: String?): Boolean = keys.containsKey(alias)
    override fun engineSize(): Int = keys.size
    override fun engineIsKeyEntry(alias: String?): Boolean = keys.containsKey(alias)
    override fun engineIsCertificateEntry(alias: String?): Boolean = false
    override fun engineGetCertificateAlias(cert: Certificate?): String? = null
    override fun engineStore(stream: OutputStream?, password: CharArray?) {}
    override fun engineLoad(stream: InputStream?, password: CharArray?) {}
}

class MockKeyStore : KeyStore(MockKeyStoreSpi(), null, "MockKeyStore")

class FakeKeyStoreContext(private val baseDir: File) : ContextWrapper(null) {
    var commitSucceeds = true
    val fakePrefs = FakeSharedPreferences { commitSucceeds }

    override fun getFilesDir(): File = File(baseDir, "files").apply { mkdirs() }
    override fun getSharedPreferences(name: String?, mode: Int): SharedPreferences {
        return fakePrefs
    }
}

class FakeSharedPreferences(private val commitPredicate: () -> Boolean = { true }) : SharedPreferences {
    val map = mutableMapOf<String, Any?>()

    override fun getAll(): MutableMap<String, *> = map
    override fun getString(key: String?, defValue: String?): String? = map[key] as? String ?: defValue
    override fun getStringSet(key: String?, defValues: MutableSet<String>?): MutableSet<String>? = defValues
    override fun getInt(key: String?, defValue: Int): Int = map[key] as? Int ?: defValue
    override fun getLong(key: String?, defValue: Long): Long = map[key] as? Long ?: defValue
    override fun getFloat(key: String?, defValue: Float): Float = map[key] as? Float ?: defValue
    override fun getBoolean(key: String?, defValue: Boolean): Boolean = map[key] as? Boolean ?: defValue
    override fun contains(key: String?): Boolean = map.containsKey(key)
    override fun edit(): SharedPreferences.Editor = FakeEditor(map, commitPredicate)
    override fun registerOnSharedPreferenceChangeListener(listener: SharedPreferences.OnSharedPreferenceChangeListener?) {}
    override fun unregisterOnSharedPreferenceChangeListener(listener: SharedPreferences.OnSharedPreferenceChangeListener?) {}

    class FakeEditor(
        private val map: MutableMap<String, Any?>,
        private val commitPredicate: () -> Boolean
    ) : SharedPreferences.Editor {
        override fun putString(key: String?, value: String?): SharedPreferences.Editor { map[key ?: ""] = value; return this }
        override fun putStringSet(key: String?, values: MutableSet<String>?): SharedPreferences.Editor { return this }
        override fun putInt(key: String?, value: Int): SharedPreferences.Editor { map[key ?: ""] = value; return this }
        override fun putLong(key: String?, value: Long): SharedPreferences.Editor { map[key ?: ""] = value; return this }
        override fun putFloat(key: String?, value: Float): SharedPreferences.Editor { map[key ?: ""] = value; return this }
        override fun putBoolean(key: String?, value: Boolean): SharedPreferences.Editor { map[key ?: ""] = value; return this }
        override fun remove(key: String?): SharedPreferences.Editor { map.remove(key); return this }
        override fun clear(): SharedPreferences.Editor { map.clear(); return this }
        override fun commit(): Boolean {
            return commitPredicate()
        }
        override fun apply() {}
    }
}

class ConfigKeyStoreTest {

    private lateinit var mockKeyStore: MockKeyStore

    @Before
    fun setUp() {
        mockKeyStore = MockKeyStore().apply { load(null) }
        ConfigKeyStore.keyStoreSupplier = { mockKeyStore }
        ConfigKeyStore.masterKeyGenerator = {
            val keyGen = KeyGenerator.getInstance("AES")
            keyGen.init(256)
            mockKeyStore.setKeyEntry("aether-config-wrap-v1", keyGen.generateKey(), null, null)
        }
    }

    @After
    fun tearDown() {
        ConfigKeyStore.keyStoreSupplier = null
        ConfigKeyStore.masterKeyGenerator = null
    }

    /**
     * A keystore that is briefly unavailable must not cost the user their
     * identity. Every exception used to route into `rotateAndRecover()`, which
     * deletes the master key and quarantines `aether.toml`, so one `keystore2`
     * hiccup after a system update silently reprovisioned the device.
     */
    @Test
    fun transientKeyStoreFailuresAreRetriedAndKeepTheIdentity() {
        val dir = File(System.getProperty("java.io.tmpdir"), "aether_ks_transient_${System.currentTimeMillis()}").apply { mkdirs() }
        val context = FakeKeyStoreContext(dir)
        val configDir = File(context.filesDir, "config").apply { mkdirs() }
        val tomlFile = File(configDir, "aether.toml")
        tomlFile.writeText("device_id = \"keep_me\"")

        val first = ConfigKeyStore.loadOrCreate(context)
        val wrappedBefore = context.fakePrefs.map["wrapped"]

        val healthy = mockKeyStore
        var calls = 0
        ConfigKeyStore.keyStoreSupplier = {
            calls += 1
            if (calls <= 2) throw java.security.UnrecoverableKeyException("keystore2 is starting")
            healthy
        }
        try {
            val again = ConfigKeyStore.loadOrCreate(context)
            assertEquals("a transient failure must not change the key", first, again)
            assertEquals("the wrapped key must survive", wrappedBefore, context.fakePrefs.map["wrapped"])
            assertTrue("expected at least three attempts, saw $calls", calls >= 3)
        } finally {
            ConfigKeyStore.keyStoreSupplier = { mockKeyStore }
        }
        assertTrue("a transient failure must not quarantine the identity", tomlFile.exists())
        dir.deleteRecursively()
    }

    /** The rotation path stays available for the case it was built for. */
    @Test
    fun anUnreadableWrappingStillRotatesAndQuarantines() {
        val dir = File(System.getProperty("java.io.tmpdir"), "aether_ks_corrupt_${System.currentTimeMillis()}").apply { mkdirs() }
        val context = FakeKeyStoreContext(dir)
        val configDir = File(context.filesDir, "config").apply { mkdirs() }
        val tomlFile = File(configDir, "aether.toml")
        tomlFile.writeText("device_id = \"stale\"")

        val first = ConfigKeyStore.loadOrCreate(context)
        // Base64 of three bytes: no IV, no GCM tag.
        context.fakePrefs.map["wrapped"] = "AQID"

        val rotated = ConfigKeyStore.loadOrCreate(context)
        assertTrue(rotated.isNotBlank())
        assertFalse("rotation must produce a new key", rotated == first)
        assertFalse("the unreadable identity must be quarantined", tomlFile.exists())
        assertTrue(
            "a fresh wrapping must be committed",
            context.fakePrefs.map["wrapped"] != null && context.fakePrefs.map["wrapped"] != "AQID",
        )
        dir.deleteRecursively()
    }

    @Test
    fun testCorruptedKeyStoreQuarantinesOldConfigFiles() {
        val tempDir = File(System.getProperty("java.io.tmpdir"), "aether_keystore_test_${System.currentTimeMillis()}").apply { mkdirs() }
        val context = FakeKeyStoreContext(tempDir)
        val configDir = File(context.filesDir, "config").apply { mkdirs() }

        val tomlFile = File(configDir, "aether.toml")
        val bakFile = File(configDir, "aether.toml.bak")
        tomlFile.writeText("corrupted_identity_data = 123")
        bakFile.writeText("corrupted_backup_data = 123")

        assertTrue(tomlFile.exists())
        assertTrue(bakFile.exists())

        // Trigger KeyStore rotation and quarantine recovery
        val recoveredKey = ConfigKeyStore.rotateAndRecover(context)
        assertNotNull(recoveredKey)
        assertTrue(recoveredKey.isNotBlank())

        // Original unreadable toml file must NOT exist at original location
        assertFalse("aether.toml must have been quarantined away", tomlFile.exists())
        assertFalse("aether.toml.bak must have been removed", bakFile.exists())

        // Corrupted file must exist as quarantine archive
        val corruptedFiles = configDir.listFiles { _, name -> name.startsWith("aether.toml.corrupted") }
        assertNotNull(corruptedFiles)
        assertTrue("Quarantined file must exist", corruptedFiles!!.isNotEmpty())
        assertEquals("corrupted_identity_data = 123", corruptedFiles[0].readText())

        tempDir.deleteRecursively()
    }

    @Test
    fun testLoadOrCreateEncryptsAndDecryptsRoundtrip() {
        val tempDir = File(System.getProperty("java.io.tmpdir"), "aether_rt_test_${System.currentTimeMillis()}").apply { mkdirs() }
        val context = FakeKeyStoreContext(tempDir)

        val key1 = ConfigKeyStore.loadOrCreate(context)
        assertNotNull(key1)
        assertTrue(key1.isNotBlank())

        // Calling loadOrCreate again should successfully unwrap and return the exact same key
        val key2 = ConfigKeyStore.loadOrCreate(context)
        assertEquals("Subsequent load must yield identical decrypted key", key1, key2)

        tempDir.deleteRecursively()
    }

    @Test
    fun testCommitFailureFailsClosed() {
        val tempDir = File(System.getProperty("java.io.tmpdir"), "aether_fail_test_${System.currentTimeMillis()}").apply { mkdirs() }
        val context = FakeKeyStoreContext(tempDir)
        context.commitSucceeds = false // Force SharedPreferences commit failure

        try {
            ConfigKeyStore.loadOrCreate(context)
            fail("Expected exception when SharedPreferences commit fails")
        } catch (e: Exception) {
            assertTrue(e.message?.contains("Failed to commit") == true || e.message?.contains("Failed to remove") == true)
        }

        tempDir.deleteRecursively()
    }
}
