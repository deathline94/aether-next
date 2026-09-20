package app.aethernext

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import java.io.File
import java.security.KeyStore
import java.security.SecureRandom
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.spec.GCMParameterSpec

object ConfigKeyStore {
    private const val TAG = "ConfigKeyStore"
    private const val ALIAS = "aether-config-wrap-v1"
    private const val PREFS_NAME = "aether_secure_config"
    private const val KEY_WRAPPED = "wrapped"

    // Injectable providers for JVM testing
    internal var keyStoreProvider: String = "AndroidKeyStore"
    internal var keyStoreSupplier: (() -> KeyStore)? = null
    internal var masterKeyGenerator: (() -> Unit)? = null

    private fun getKeyStore(): KeyStore {
        return keyStoreSupplier?.invoke()
            ?: KeyStore.getInstance(keyStoreProvider).apply { load(null) }
    }

    fun loadOrCreate(context: Context): String {
        return try {
            getOrGenerate(context)
        } catch (e: Exception) {
            Log.w(TAG, "Crypto failure in key store, attempting rotation recovery: ${e.message}", e)
            rotateAndRecover(context)
        }
    }

    fun rotateAndRecover(context: Context): String {
        try {
            val ks = getKeyStore()
            if (ks.containsAlias(ALIAS)) {
                ks.deleteEntry(ALIAS)
            }
        } catch (e: Exception) {
            Log.w(TAG, "Failed to delete corrupted KeyStore entry: ${e.message}")
        }
        val p = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val commitOk = p.edit().remove(KEY_WRAPPED).commit()
        if (!commitOk) {
            throw IllegalStateException("Failed to remove wrapped key from SharedPreferences during recovery")
        }

        // Quarantine corrupted aether.toml and delete aether.toml.bak
        val configDir = File(context.filesDir, "config")
        val configFile = File(configDir, "aether.toml")
        val bakFile = File(configDir, "aether.toml.bak")
        if (configFile.exists()) {
            val quarantineFile = File(configDir, "aether.toml.corrupted.${System.currentTimeMillis()}")
            val renamed = configFile.renameTo(quarantineFile)
            if (!renamed) {
                val deleted = configFile.delete()
                if (!deleted && configFile.exists()) {
                    throw IllegalStateException("Failed to quarantine or delete corrupted aether.toml")
                }
            }
        }
        if (bakFile.exists()) {
            val deleted = bakFile.delete()
            if (!deleted && bakFile.exists()) {
                throw IllegalStateException("Failed to delete backup aether.toml.bak")
            }
        }

        Log.i(TAG, "KeyStore rotated and corrupted config quarantined; emitting reprovision signal")
        SessionController.getOrNull()?.let { sc ->
            sc.emitLog("KeyStore recovered: corrupted identity quarantined, reprovisioning required")
        }

        return getOrGenerate(context)
    }

    private fun getOrGenerate(context: Context): String {
        val ks = getKeyStore()
        if (!ks.containsAlias(ALIAS)) {
            if (masterKeyGenerator != null) {
                masterKeyGenerator!!.invoke()
            } else {
                generateMasterKey()
            }
        }
        val key = ks.getKey(ALIAS, null)
            ?: throw IllegalStateException("KeyStore key missing for alias $ALIAS")

        val p = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val saved = p.getString(KEY_WRAPPED, null)

        val raw = if (saved == null) {
            val freshKey = ByteArray(32).also { SecureRandom().nextBytes(it) }
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, key)
            val iv = cipher.iv
            val ciphertext = cipher.doFinal(freshKey)
            val committed = p.edit().putString(KEY_WRAPPED, Base64.getEncoder().encodeToString(iv + ciphertext)).commit()
            if (!committed) {
                throw IllegalStateException("Failed to commit wrapped config key to SharedPreferences")
            }
            freshKey
        } else {
            val b = Base64.getDecoder().decode(saved)
            require(b.size >= 12 + 16) { "Encrypted payload too short" }
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, b.copyOfRange(0, 12)))
            cipher.doFinal(b.copyOfRange(12, b.size))
        }
        return Base64.getEncoder().encodeToString(raw)
    }

    private fun generateMasterKey() {
        val g = KeyGenerator.getInstance("AES", keyStoreProvider)
        val spec = KeyGenParameterSpec.Builder(
            ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .build()
        g.init(spec)
        g.generateKey()
    }
}