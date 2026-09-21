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

    // Three retries with escalating backoff: a keystore service that is
    // restarting comes back within a second, a slow one within a few.
    private val RETRY_DELAYS_MS = listOf(200L, 1000L, 3000L)

    // Injectable providers for JVM testing
    internal var keyStoreProvider: String = "AndroidKeyStore"
    internal var keyStoreSupplier: (() -> KeyStore)? = null
    internal var masterKeyGenerator: (() -> Unit)? = null

    private fun getKeyStore(): KeyStore {
        return keyStoreSupplier?.invoke()
            ?: KeyStore.getInstance(keyStoreProvider).apply { load(null) }
    }

    /**
     * The wrapped key cannot be decrypted and the material behind it is gone.
     * Distinct from a keystore/service failure, which is worth retrying.
     */
    class CorruptWrappingException(message: String, cause: Throwable? = null) :
        Exception(message, cause)

    /**
     * Transient = the keystore provider, its process, or the key service was
     * briefly unavailable. Nothing is wrong with the stored key.
     */
    internal fun isTransient(e: Throwable): Boolean {
        var t: Throwable? = e
        while (t != null) {
            when (t) {
                is java.security.KeyStoreException,
                is java.security.UnrecoverableKeyException,
                is java.security.ProviderException,
                -> return true
            }
            t = t.cause
        }
        return false
    }

    /**
     * Permanent = the wrapping itself is unreadable: bad GCM tag, or a blob too
     * short to contain an IV and a tag. Only this justifies destroying the key.
     */
    internal fun isCorruptWrapping(e: Throwable): Boolean {
        var t: Throwable? = e
        while (t != null) {
            if (t is javax.crypto.BadPaddingException ||
                t is java.security.InvalidAlgorithmParameterException ||
                t is CorruptWrappingException
            ) {
                return true
            }
            if (t is IllegalArgumentException &&
                t.message?.contains("too short", ignoreCase = true) == true
            ) {
                return true
            }
            t = t.cause
        }
        return false
    }

    /**
     * Load, generating on first use.
     *
     * Any exception used to fall into `rotateAndRecover()`, which deletes the
     * master key and quarantines the identity: one transient `keystore2` hiccup
     * after a system update cost the user their device permanently, and they
     * would not even know it had happened until a reprovision. Transient faults
     * are retried and then surfaced; only a genuinely unreadable wrapping is
     * allowed to trigger rotation.
     */
    fun loadOrCreate(context: Context): String {
        var last: Exception? = null
        for (attempt in 0..RETRY_DELAYS_MS.size) {
            try {
                return getOrGenerate(context)
            } catch (e: Exception) {
                if (isCorruptWrapping(e)) {
                    Log.w(TAG, "config key wrapping is unreadable; rotating: ${e.message}", e)
                    return rotateAndRecover(context)
                }
                if (!isTransient(e)) {
                    Log.w(TAG, "unexpected key-store failure; propagating: ${e.message}", e)
                    throw e
                }
                last = e
                if (attempt == RETRY_DELAYS_MS.size) break
                Log.w(
                    TAG,
                    "transient key-store failure (attempt ${attempt + 1}, retrying in " +
                        "${RETRY_DELAYS_MS[attempt]}ms): ${e.message}",
                )
                Thread.sleep(RETRY_DELAYS_MS[attempt])
            }
        }
        // Surfaced, not swallowed: a keystore that never came back is a real
        // failure the user must see, and it must not cost them the key.
        throw last ?: IllegalStateException("key store unavailable")
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
            if (b.size < 12 + 16) {
                // 12-byte IV + 16-byte GCM tag at minimum. Throwing the classified
                // exception is what lets `loadOrCreate` tell a truncated blob
                // apart from a service that is merely busy.
                throw CorruptWrappingException("wrapped config key is truncated (${b.size} bytes)")
            }
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