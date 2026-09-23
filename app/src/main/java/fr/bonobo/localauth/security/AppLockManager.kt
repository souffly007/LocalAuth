package fr.bonobo.localauth.security

import android.content.Context
import android.util.Base64
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec

class AppLockManager(context: Context) {
    private val prefs = context.getSharedPreferences("localauth_lock", Context.MODE_PRIVATE)
    fun hasPin() = prefs.contains("pin_hash") && prefs.contains("pin_salt")

    fun setPin(pin: CharArray) {
        require(pin.size == 6 && pin.all(Char::isDigit)) { "Le code doit contenir exactement 6 chiffres" }
        val salt = ByteArray(16).also(SecureRandom()::nextBytes)
        val hash = derive(pin, salt)
        prefs.edit().putString("pin_salt", b64(salt)).putString("pin_hash", b64(hash)).apply()
        pin.fill('\u0000'); hash.fill(0)
    }

    fun verify(pin: CharArray): Boolean {
        val salt = prefs.getString("pin_salt", null)?.let(::unb64) ?: return false
        val expected = prefs.getString("pin_hash", null)?.let(::unb64) ?: return false
        val actual = derive(pin, salt)
        pin.fill('\u0000')
        return MessageDigest.isEqual(expected, actual).also { actual.fill(0); expected.fill(0) }
    }

    private fun derive(pin: CharArray, salt: ByteArray): ByteArray =
        SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(PBEKeySpec(pin, salt, 180_000, 256)).encoded
    private fun b64(value: ByteArray) = Base64.encodeToString(value, Base64.NO_WRAP)
    private fun unb64(value: String) = Base64.decode(value, Base64.NO_WRAP)
}
