package app.aethernext
import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.KeyStore
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.spec.GCMParameterSpec
object ConfigKeyStore {
 private const val ALIAS="aether-config-wrap-v1"
 fun loadOrCreate(c: Context): String {
  val ks=KeyStore.getInstance("AndroidKeyStore").apply{load(null)}
  if(!ks.containsAlias(ALIAS)){ val g=KeyGenerator.getInstance("AES","AndroidKeyStore"); g.init(KeyGenParameterSpec.Builder(ALIAS,3).setBlockModes(KeyProperties.BLOCK_MODE_GCM).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE).build()); g.generateKey() }
  val key=ks.getKey(ALIAS,null); val p=c.getSharedPreferences("aether_secure_config",Context.MODE_PRIVATE); val saved=p.getString("wrapped",null)
  val raw=if(saved==null){ ByteArray(32).also{SecureRandom().nextBytes(it)}.also{v->val x=Cipher.getInstance("AES/GCM/NoPadding");x.init(Cipher.ENCRYPT_MODE,key);p.edit().putString("wrapped",Base64.encodeToString(x.iv+x.doFinal(v),Base64.NO_WRAP)).commit()} } else { val b=Base64.decode(saved,Base64.NO_WRAP);val x=Cipher.getInstance("AES/GCM/NoPadding");x.init(Cipher.DECRYPT_MODE,key,GCMParameterSpec(128,b.copyOfRange(0,12)));x.doFinal(b.copyOfRange(12,b.size)) }
  return Base64.encodeToString(raw,Base64.NO_WRAP)
 }
}