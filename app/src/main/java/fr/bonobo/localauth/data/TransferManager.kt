package fr.bonobo.localauth.data

import android.net.Uri
import android.util.Base64
import org.json.JSONArray
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.net.URLDecoder
import java.net.URLEncoder
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec
import org.bouncycastle.crypto.generators.Argon2BytesGenerator
import org.bouncycastle.crypto.params.Argon2Parameters

data class ImportResult(val accounts: List<PortableAccount>, val source: String)

object TransferManager {
    private const val iterations = 210_000

    fun parseOtpAuth(value: String): PortableAccount {
        val uri = Uri.parse(value.trim())
        require(uri.scheme == "otpauth" && uri.host == "totp") { "QR TOTP non compatible" }
        val rawLabel = URLDecoder.decode(uri.path.orEmpty().removePrefix("/"), "UTF-8")
        val issuerFromLabel = rawLabel.substringBefore(':', "")
        val label = rawLabel.substringAfter(':', rawLabel)
        val issuer = uri.getQueryParameter("issuer")?.takeIf { it.isNotBlank() } ?: issuerFromLabel.ifBlank { "Compte TOTP" }
        return PortableAccount(
            issuer, label, uri.getQueryParameter("secret") ?: error("Clé secrète absente"),
            uri.getQueryParameter("digits")?.toIntOrNull()?.takeIf { it == 6 || it == 8 } ?: 6,
            uri.getQueryParameter("period")?.toIntOrNull()?.coerceIn(15, 120) ?: 30,
            uri.getQueryParameter("algorithm")?.uppercase()?.takeIf { it in setOf("SHA1", "SHA256", "SHA512") } ?: "SHA1"
        )
    }

    fun parseQr(value: String): ImportResult = when {
        value.startsWith("otpauth://") -> ImportResult(listOf(parseOtpAuth(value)), "QR TOTP")
        value.startsWith("otpauth-migration://") -> ImportResult(parseGoogleMigration(value), "Google Authenticator")
        else -> error("Ce QR code ne contient pas de compte TOTP")
    }

    fun encryptedBackup(accounts: List<PortableAccount>, password: CharArray): ByteArray {
        require(password.size >= 8) { "Le mot de passe doit contenir au moins 8 caractères" }
        val payload = JSONObject().put("format", "LocalAuth").put("version", 1).put("accounts", JSONArray().apply {
            accounts.forEach { put(JSONObject().put("issuer", it.issuer).put("label", it.label).put("secret", it.secret).put("digits", it.digits).put("period", it.period).put("algorithm", it.algorithm)) }
        }).toString().encodeToByteArray()
        val salt = ByteArray(16).also(SecureRandom()::nextBytes)
        val iv = ByteArray(12).also(SecureRandom()::nextBytes)
        val key = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(PBEKeySpec(password, salt, iterations, 256)).encoded
        val encrypted = Cipher.getInstance("AES/GCM/NoPadding").run { init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, iv)); doFinal(payload) }
        password.fill('\u0000'); key.fill(0)
        return JSONObject().put("format", "LocalAuthEncryptedBackup").put("version", 1).put("kdf", "PBKDF2-HMAC-SHA256").put("iterations", iterations)
            .put("salt", b64(salt)).put("iv", b64(iv)).put("ciphertext", b64(encrypted)).toString(2).encodeToByteArray()
    }

    fun importBytes(bytes: ByteArray, password: CharArray): ImportResult {
        val text = bytes.decodeToString().trim()
        if (text.startsWith("otpauth")) return parseQr(text)
        val root = JSONObject(text)
        if (root.optString("format") == "LocalAuthEncryptedBackup") {
            require(password.isNotEmpty()) { "Mot de passe requis" }
            val salt = unb64(root.getString("salt")); val iv = unb64(root.getString("iv")); val encrypted = unb64(root.getString("ciphertext"))
            val key = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(PBEKeySpec(password, salt, root.optInt("iterations", iterations), 256)).encoded
            val clear = try { Cipher.getInstance("AES/GCM/NoPadding").run { init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, iv)); doFinal(encrypted) } } catch (_: Exception) { error("Mot de passe incorrect ou sauvegarde endommagée") } finally { password.fill('\u0000'); key.fill(0) }
            return parseLocal(JSONObject(clear.decodeToString()))
        }
        if (root.optString("format") == "LocalAuth") return parseLocal(root)
        if (root.has("entries") && root.optJSONArray("entries")?.optJSONObject(0)?.has("content") == true) return parseProton(root)
        if (root.has("salt") && root.has("content")) return parseProtonEncrypted(root, password)
        return parseAegis(root)
    }

    private fun parseLocal(root: JSONObject): ImportResult = ImportResult(parseArray(root.getJSONArray("accounts")), "Sauvegarde LocalAuth")
    private fun parseArray(array: JSONArray) = (0 until array.length()).map { i -> array.getJSONObject(i).let { PortableAccount(it.optString("issuer", "Compte TOTP"), it.optString("label"), it.getString("secret"), it.optInt("digits", 6), it.optInt("period", 30), it.optString("algorithm", "SHA1").uppercase()) } }

    private fun parseAegis(root: JSONObject): ImportResult {
        val db = root.optJSONObject("db") ?: root
        val array = db.optJSONArray("entries") ?: error("Format de sauvegarde non reconnu")
        val items = (0 until array.length()).mapNotNull { i ->
            val e = array.optJSONObject(i) ?: return@mapNotNull null
            if (e.optString("type", "totp") != "totp") return@mapNotNull null
            val info = e.optJSONObject("info") ?: return@mapNotNull null
            PortableAccount(e.optString("issuer", "Compte TOTP"), e.optString("name"), info.optString("secret"), info.optInt("digits", 6), info.optInt("period", 30), info.optString("algo", "SHA1").uppercase().replace("SHA-", "SHA"))
        }
        require(items.isNotEmpty()) { "Aucun compte TOTP trouvé dans cette sauvegarde Aegis" }
        return ImportResult(items, "Aegis (JSON non chiffré)")
    }

    private fun parseProton(root: JSONObject): ImportResult {
        require(root.optInt("version", 0) == 1) { "Version d'export Proton non prise en charge" }
        val entries = root.getJSONArray("entries")
        val items = (0 until entries.length()).mapNotNull { i ->
            val content = entries.optJSONObject(i)?.optJSONObject("content") ?: return@mapNotNull null
            if (!content.optString("entry_type", "Totp").equals("Totp", ignoreCase = true)) return@mapNotNull null
            val uri = content.optString("uri")
            if (!uri.startsWith("otpauth://totp/")) return@mapNotNull null
            parseOtpAuth(uri).let { parsed ->
                if (parsed.label.isBlank()) parsed.copy(label = content.optString("name")) else parsed
            }
        }
        require(items.isNotEmpty()) { "Aucun compte TOTP compatible trouvé dans l'export Proton" }
        return ImportResult(items, "Proton Authenticator")
    }

    private fun parseProtonEncrypted(root: JSONObject, password: CharArray): ImportResult {
        require(root.optInt("version", 0) == 1) { "Version d'export Proton chiffré non prise en charge" }
        require(password.isNotEmpty()) { "Mot de passe Proton requis" }
        val salt = unb64(root.getString("salt"))
        require(salt.size == 16) { "Sauvegarde Proton invalide" }
        val key = ByteArray(32)
        try {
            val params = Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                .withVersion(Argon2Parameters.ARGON2_VERSION_13)
                .withSalt(salt).withMemoryAsKB(19 * 1024).withIterations(2).withParallelism(1).build()
            Argon2BytesGenerator().apply { init(params) }.generateBytes(password, key)
            val packed = unb64(root.getString("content"))
            require(packed.size > 28) { "Sauvegarde Proton endommagée" }
            val iv = packed.copyOfRange(0, 12)
            val encrypted = packed.copyOfRange(12, packed.size)
            val clear = try {
                Cipher.getInstance("AES/GCM/NoPadding").run {
                    init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, iv))
                    updateAAD("proton.authenticator.export.v1".encodeToByteArray())
                    doFinal(encrypted)
                }
            } catch (_: Exception) { error("Mot de passe Proton incorrect ou fichier endommagé") }
            return parseProton(JSONObject(clear.decodeToString()))
        } finally {
            password.fill('\u0000'); key.fill(0)
        }
    }

    private fun parseGoogleMigration(value: String): List<PortableAccount> {
        val data = Uri.parse(value).getQueryParameter("data") ?: error("Données de migration absentes")
        val decoded = Base64.decode(data, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
        return ProtoReader(decoded).fields().filter { it.first == 1 }.map { (_, raw) ->
            val f = ProtoReader(raw).fields().groupBy({ it.first }, { it.second })
            val secret = base32(f[1]?.firstOrNull() ?: error("Secret absent"))
            val name = f[2]?.firstOrNull()?.decodeToString().orEmpty()
            val issuer = f[3]?.firstOrNull()?.decodeToString()?.ifBlank { "Compte TOTP" } ?: "Compte TOTP"
            val algorithm = when (f[4]?.firstOrNull()?.firstOrNull()?.toInt()) { 2 -> "SHA256"; 3 -> "SHA512"; else -> "SHA1" }
            val digits = if (f[5]?.firstOrNull()?.firstOrNull()?.toInt() == 2) 8 else 6
            PortableAccount(issuer, name, secret, digits, 30, algorithm)
        }.also { require(it.isNotEmpty()) { "Aucun compte trouvé dans le QR de migration" } }
    }

    private class ProtoReader(private val data: ByteArray) {
        private var p = 0
        private fun varint(): Long { var r = 0L; var s = 0; while (p < data.size) { val b = data[p++].toInt() and 255; r = r or ((b and 127).toLong() shl s); if (b and 128 == 0) return r; s += 7 }; error("Protobuf incomplet") }
        fun fields(): List<Pair<Int, ByteArray>> { val out = mutableListOf<Pair<Int, ByteArray>>(); while (p < data.size) { val tag = varint().toInt(); val n = tag ushr 3; when (tag and 7) { 0 -> out += n to byteArrayOf(varint().toByte()); 2 -> { val l = varint().toInt(); out += n to data.copyOfRange(p, p + l); p += l }; 1 -> p += 8; 5 -> p += 4; else -> error("Protobuf non pris en charge") } }; return out }
    }

    private fun base32(bytes: ByteArray): String { val abc = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"; val out = StringBuilder(); var buffer = 0; var bits = 0; bytes.forEach { buffer = (buffer shl 8) or (it.toInt() and 255); bits += 8; while (bits >= 5) { bits -= 5; out.append(abc[(buffer shr bits) and 31]) } }; if (bits > 0) out.append(abc[(buffer shl (5 - bits)) and 31]); return out.toString() }
    private fun b64(v: ByteArray) = Base64.encodeToString(v, Base64.NO_WRAP)
    private fun unb64(v: String) = Base64.decode(v, Base64.NO_WRAP)
}
