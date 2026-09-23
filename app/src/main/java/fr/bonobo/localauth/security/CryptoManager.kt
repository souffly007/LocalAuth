package fr.bonobo.localauth.security

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import android.util.Base64

data class EncryptedValue(val ciphertext: String, val iv: String)

class CryptoManager {
    private val alias = "localauth_secrets_v1"
    private val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    private fun key(): SecretKey {
        (keyStore.getKey(alias, null) as? SecretKey)?.let { return it }
        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").apply {
            init(KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setKeySize(256).setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE).build())
        }.generateKey()
    }
    fun encrypt(value: ByteArray): EncryptedValue {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.ENCRYPT_MODE, key()) }
        return EncryptedValue(Base64.encodeToString(cipher.doFinal(value), Base64.NO_WRAP), Base64.encodeToString(cipher.iv, Base64.NO_WRAP))
    }
    fun decrypt(ciphertext: String, iv: String): ByteArray = Cipher.getInstance("AES/GCM/NoPadding").run {
        init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, Base64.decode(iv, Base64.NO_WRAP)))
        doFinal(Base64.decode(ciphertext, Base64.NO_WRAP))
    }
}
