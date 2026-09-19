package app.aethernext

import android.content.Context
import android.content.ContextWrapper
import android.content.SharedPreferences
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

class FakeKeyStoreContext(private val baseDir: File) : ContextWrapper(null) {
    override fun getFilesDir(): File = File(baseDir, "files").apply { mkdirs() }
    override fun getSharedPreferences(name: String?, mode: Int): SharedPreferences {
        return FakeSharedPreferences()
    }
}

class FakeSharedPreferences : SharedPreferences {
    private val map = mutableMapOf<String, Any?>()

    override fun getAll(): MutableMap<String, *> = map
    override fun getString(key: String?, defValue: String?): String? = map[key] as? String ?: defValue
    override fun getStringSet(key: String?, defValues: MutableSet<String>?): MutableSet<String>? = defValues
    override fun getInt(key: String?, defValue: Int): Int = map[key] as? Int ?: defValue
    override fun getLong(key: String?, defValue: Long): Long = map[key] as? Long ?: defValue
    override fun getFloat(key: String?, defValue: Float): Float = map[key] as? Float ?: defValue
    override fun getBoolean(key: String?, defValue: Boolean): Boolean = map[key] as? Boolean ?: defValue
    override fun contains(key: String?): Boolean = map.containsKey(key)
    override fun edit(): SharedPreferences.Editor = FakeEditor(map)
    override fun registerOnSharedPreferenceChangeListener(listener: SharedPreferences.OnSharedPreferenceChangeListener?) {}
    override fun unregisterOnSharedPreferenceChangeListener(listener: SharedPreferences.OnSharedPreferenceChangeListener?) {}

    class FakeEditor(private val map: MutableMap<String, Any?>) : SharedPreferences.Editor {
        override fun putString(key: String?, value: String?): SharedPreferences.Editor { map[key ?: ""] = value; return this }
        override fun putStringSet(key: String?, values: MutableSet<String>?): SharedPreferences.Editor { return this }
        override fun putInt(key: String?, value: Int): SharedPreferences.Editor { map[key ?: ""] = value; return this }
        override fun putLong(key: String?, value: Long): SharedPreferences.Editor { map[key ?: ""] = value; return this }
        override fun putFloat(key: String?, value: Float): SharedPreferences.Editor { map[key ?: ""] = value; return this }
        override fun putBoolean(key: String?, value: Boolean): SharedPreferences.Editor { map[key ?: ""] = value; return this }
        override fun remove(key: String?): SharedPreferences.Editor { map.remove(key); return this }
        override fun clear(): SharedPreferences.Editor { map.clear(); return this }
        override fun commit(): Boolean = true
        override fun apply() {}
    }
}

class ConfigKeyStoreTest {

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
}
