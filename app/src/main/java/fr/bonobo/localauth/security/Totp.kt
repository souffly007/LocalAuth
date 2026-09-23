package fr.bonobo.localauth.security

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

object Totp {
    private const val alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    fun normalize(secret: String) = secret.uppercase().filterNot { it.isWhitespace() || it == '-' || it == '=' }
    private fun decode(secret: String): ByteArray {
        var buffer = 0; var bits = 0; val out = ArrayList<Byte>()
        for (c in normalize(secret)) {
            val value = alphabet.indexOf(c); require(value >= 0) { "Clé Base32 invalide" }
            buffer = (buffer shl 5) or value; bits += 5
            if (bits >= 8) { bits -= 8; out += ((buffer shr bits) and 0xff).toByte() }
        }
        return out.toByteArray()
    }
    fun code(secret: String, timeMillis: Long = System.currentTimeMillis(), period: Int = 30, digits: Int = 6, algorithm: String = "SHA1"): String {
        val counter = timeMillis / 1000 / period
        val msg = ByteArray(8) { i -> (counter ushr (56 - 8 * i)).toByte() }
        val hash = Mac.getInstance("Hmac$algorithm").run { init(SecretKeySpec(decode(secret), "Hmac$algorithm")); doFinal(msg) }
        val offset = hash.last().toInt() and 0x0f
        val binary = ((hash[offset].toInt() and 0x7f) shl 24) or ((hash[offset+1].toInt() and 0xff) shl 16) or ((hash[offset+2].toInt() and 0xff) shl 8) or (hash[offset+3].toInt() and 0xff)
        val mod = if (digits == 8) 100_000_000 else 1_000_000
        return (binary % mod).toString().padStart(digits, '0')
    }
}
