package app.aethernext

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
import java.security.KeyStore
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.spec.GCMParameterSpec

object ConfigKeyStore {
    private const val TAG = "ConfigKeyStore"
    private const val ALIAS = "aether-config-wrap-v1"
    private const val PREFS_NAME = "aether_secure_config"
    private const val KEY_WRAPPED = "wrapped"

    fun loadOrCreate(context: Context): String {
        return try {
            getOrGenerate(context)
        } catch (e: Exception) {
            Log.w(TAG, "Crypto failure in key store, attempting rotation recovery: ${e.message}", e)
            rotateAndRecover(context)
        }
    }

    private fun getOrGenerate(context: Context): String {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        if (!ks.containsAlias(ALIAS)) {
            generateMasterKey()
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
            p.edit().putString(KEY_WRAPPED, Base64.encodeToString(iv + ciphertext, Base64.NO_WRAP)).commit()
            freshKey
        } else {
            val b = Base64.decode(saved, Base64.NO_WRAP)
            require(b.size >= 12 + 16) { "Encrypted payload too short" }
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, b.copyOfRange(0, 12)))
            cipher.doFinal(b.copyOfRange(12, b.size))
        }
        return Base64.encodeToString(raw, Base64.NO_WRAP)
    }

    private fun rotateAndRecover(context: Context): String {
        try {
            val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            if (ks.containsAlias(ALIAS)) {
                ks.deleteEntry(ALIAS)
            }
        } catch (e: Exception) {
            Log.w(TAG, "Failed to delete corrupted KeyStore entry: ${e.message}")
        }
        val p = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        p.edit().remove(KEY_WRAPPED).commit()

        return getOrGenerate(context)
    }

    private fun generateMasterKey() {
        val g = KeyGenerator.getInstance("AES", "AndroidKeyStore")
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