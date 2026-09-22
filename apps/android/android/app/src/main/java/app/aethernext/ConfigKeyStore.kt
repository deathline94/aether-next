package app.aethernext

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import java.io.File
import java.security.Key
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

    /**
     * Second copy, written first and cleared last.
     *
     * With a single slot, an interrupt between "the keystore generated a new
     * master key" and "its wrapped form reached disk" leaves the config
     * encrypted under a key that no longer exists anywhere — the next read is an
     * authentication failure, which is classified as corruption, which rotates,
     * which quarantines the identity. Staging means every interrupted write still
     * has a committed, decryptable copy of the thing it was writing.
     */
    private const val KEY_WRAPPED_STAGING = "wrapped_staging"

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
        // Both slots: leaving the staging copy behind would let the next start
        // "recover" the wrapping of the key we have just destroyed.
        val commitOk = p.edit().remove(KEY_WRAPPED).remove(KEY_WRAPPED_STAGING).commit()
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

    private fun unwrap(key: Key, saved: String): ByteArray {
        val b = Base64.getDecoder().decode(saved)
        if (b.size < 12 + 16) {
            // 12-byte IV + 16-byte GCM tag at minimum. Throwing the classified
            // exception is what lets `loadOrCreate` tell a truncated blob apart
            // from a service that is merely busy.
            throw CorruptWrappingException("wrapped config key is truncated (${b.size} bytes)")
        }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, b.copyOfRange(0, 12)))
        return cipher.doFinal(b.copyOfRange(12, b.size))
    }

    private fun wrap(key: Key, raw: ByteArray): String {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key)
        return Base64.getEncoder().encodeToString(cipher.iv + cipher.doFinal(raw))
    }

    /** Commit a value to a prefs slot, refusing to pretend a failed commit worked. */
    private fun commit(p: android.content.SharedPreferences, key: String, value: String) {
        if (!p.edit().putString(key, value).commit()) {
            throw IllegalStateException("Failed to commit $key to SharedPreferences")
        }
    }

    private fun getOrGenerate(context: Context): String {
        val ks = getKeyStore()
        val p = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

        // A committed wrapping is read *before* any key is generated: the old
        // order could mint a fresh master key, then discover the stored blob, and
        // leave the two permanently unable to agree.
        val keyFor: () -> Key = {
            ks.getKey(ALIAS, null) ?: throw IllegalStateException("KeyStore key missing for alias $ALIAS")
        }
        val saved = p.getString(KEY_WRAPPED, null)
        if (saved != null) {
            return Base64.getEncoder().encodeToString(unwrap(keyFor(), saved))
        }

        // The authoritative slot is gone but the staging copy survived: that is an
        // interrupted promotion, not a new install. Recover it rather than
        // generating a second key that orphans the config encrypted under the first.
        val staged = p.getString(KEY_WRAPPED_STAGING, null)
        if (staged != null) {
            val raw = unwrap(keyFor(), staged)
            commit(p, KEY_WRAPPED, staged)
            p.edit().remove(KEY_WRAPPED_STAGING).apply()
            Log.i(TAG, "recovered the config key from the staging slot after an interrupted promotion")
            return Base64.getEncoder().encodeToString(raw)
        }

        if (!ks.containsAlias(ALIAS)) {
            if (masterKeyGenerator != null) {
                masterKeyGenerator!!.invoke()
            } else {
                generateMasterKey()
            }
        }
        val key = keyFor()
        val freshKey = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val wrapped = wrap(key, freshKey)
        // Read the wrapping back through the keystore key before either slot is
        // trusted: a copy that cannot be decrypted here is not a copy at all.
        if (!unwrap(key, wrapped).contentEquals(freshKey)) {
            throw CorruptWrappingException("freshly wrapped config key failed its read-back check")
        }
        commit(p, KEY_WRAPPED_STAGING, wrapped)
        commit(p, KEY_WRAPPED, wrapped)
        p.edit().remove(KEY_WRAPPED_STAGING).apply()
        return Base64.getEncoder().encodeToString(freshKey)
    }

    private fun generateMasterKey() {
        val g = KeyGenerator.getInstance("AES", keyStoreProvider)
        val builder = KeyGenParameterSpec.Builder(
            ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            // Both are today's defaults, and both are load-bearing for an
            // unattended tunnel: a key that a biometric enrollment can invalidate
            // is a key that can silently stop decrypting the identity.
            .setUserAuthenticationRequired(false)
            .setInvalidatedByBiometricEnrollment(false)
        // `setRollbackResistant(true)` was the other half of this task. It is not
        // reachable here: the symbol does not exist anywhere under
        // `android.security`/`android.hardware` in the android-34 platform jar this
        // project compiles against (verified with javap and a jar-wide search),
        // because rollback resistance is a KeyMint tag rather than a published
        // AndroidKeyStore builder option. The durable copy below is what actually
        // protects this key today; see KEY_WRAPPED_STAGING.
        g.init(builder.build())
        g.generateKey()
    }
}