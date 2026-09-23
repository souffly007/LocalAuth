package fr.bonobo.localauth.data

import fr.bonobo.localauth.security.CryptoManager
import fr.bonobo.localauth.security.Totp
import kotlinx.coroutines.flow.map

class AccountRepository(private val dao: AccountDao, private val crypto: CryptoManager = CryptoManager()) {
    val accounts = dao.observeAll().map { rows ->
        rows.map(::decryptAccount).sortedWith(compareBy<Account> { it.issuer.lowercase() }.thenBy { it.label.lowercase() })
    }
    suspend fun add(issuer: String, label: String, secret: String, digits: Int = 6, period: Int = 30, algorithm: String = "SHA1"): Boolean {
        require(issuer.isNotBlank() && secret.isNotBlank())
        val normalized = Totp.normalize(secret)
        Totp.code(normalized, digits = digits, period = period, algorithm = algorithm)
        if (dao.getAll().any { runCatching { decrypt(it.secretCiphertext, it.secretIv) == normalized }.getOrDefault(false) }) return false
        val encryptedIssuer = crypto.encrypt(issuer.trim().encodeToByteArray())
        val encryptedLabel = crypto.encrypt(label.trim().encodeToByteArray())
        val encryptedSecret = crypto.encrypt(normalized.encodeToByteArray())
        dao.insert(AccountEntity(issuerCiphertext = encryptedIssuer.ciphertext, issuerIv = encryptedIssuer.iv,
            labelCiphertext = encryptedLabel.ciphertext, labelIv = encryptedLabel.iv,
            secretCiphertext = encryptedSecret.ciphertext, secretIv = encryptedSecret.iv,
            digits = digits, period = period, algorithm = algorithm))
        return true
    }
    suspend fun exportable() = dao.getAll().map(::decryptAccount).map { PortableAccount(it.issuer, it.label, secret(it), it.digits, it.period, it.algorithm) }
    fun secret(account: Account) = decrypt(account.secretCiphertext, account.secretIv)
    suspend fun delete(account: Account) = dao.deleteById(account.id)
    private fun decryptAccount(row: AccountEntity) = Account(row.id,
        decrypt(row.issuerCiphertext, row.issuerIv), decrypt(row.labelCiphertext, row.labelIv),
        row.secretCiphertext, row.secretIv, row.digits, row.period, row.algorithm, row.createdAt)
    private fun decrypt(ciphertext: String, iv: String) = crypto.decrypt(ciphertext, iv).decodeToString()
}

data class PortableAccount(val issuer: String, val label: String, val secret: String, val digits: Int = 6, val period: Int = 30, val algorithm: String = "SHA1")
