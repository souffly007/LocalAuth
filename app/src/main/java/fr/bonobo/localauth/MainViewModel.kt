package fr.bonobo.localauth

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import fr.bonobo.localauth.data.AccountRepository
import fr.bonobo.localauth.data.TransferManager
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch

class MainViewModel(app: Application) : AndroidViewModel(app) {
    val repository = AccountRepository((app as LocalAuthApp).db.accounts())
    val accounts = repository.accounts.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), emptyList())
    fun add(issuer: String, label: String, secret: String, onError: (String) -> Unit) = viewModelScope.launch {
        runCatching { repository.add(issuer, label, secret) }.onFailure { onError(it.message ?: "Données invalides") }
    }
    fun delete(account: fr.bonobo.localauth.data.Account) = viewModelScope.launch { repository.delete(account) }
    fun importQr(value: String, done: (String) -> Unit) = viewModelScope.launch {
        runCatching { importAccounts(TransferManager.parseQr(value)) }.fold({ done(it) }, { done("Erreur : ${it.message}") })
    }
    fun importFile(bytes: ByteArray, password: CharArray, done: (String) -> Unit) = viewModelScope.launch {
        runCatching { importAccounts(TransferManager.importBytes(bytes, password)) }.fold({ done(it) }, { done("Erreur : ${it.message}") })
    }
    suspend fun exportBackup(password: CharArray) = TransferManager.encryptedBackup(repository.exportable(), password)
    private suspend fun importAccounts(result: fr.bonobo.localauth.data.ImportResult): String {
        var added = 0; var duplicates = 0
        result.accounts.forEach { if (repository.add(it.issuer, it.label, it.secret, it.digits, it.period, it.algorithm)) added++ else duplicates++ }
        return "${result.source} : $added ajouté(s), $duplicates doublon(s) ignoré(s)"
    }
}
