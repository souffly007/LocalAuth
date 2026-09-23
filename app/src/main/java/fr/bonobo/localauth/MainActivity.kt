package fr.bonobo.localauth

import android.os.Bundle
import android.view.WindowManager
import androidx.fragment.app.FragmentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.viewModels
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.FileDownload
import androidx.compose.material.icons.filled.FileUpload
import androidx.compose.material.icons.filled.QrCodeScanner
import androidx.compose.material.icons.filled.Fingerprint
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import fr.bonobo.localauth.data.Account
import fr.bonobo.localauth.security.Totp
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import fr.bonobo.localauth.security.AppLockManager

class MainActivity : FragmentActivity() {
    private val vm by viewModels<MainViewModel>()
    private val unlocked = mutableStateOf(false)
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        enableEdgeToEdge()
        val lock = AppLockManager(this)
        setContent { LocalAuthTheme { if (unlocked.value) Home(vm) else LockScreen(this, lock) { unlocked.value = true } } }
    }
    override fun onStop() {
        super.onStop()
        if (!isChangingConfigurations) unlocked.value = false
    }
}

private val Navy = Color(0xFF090D1D)
private val Violet = Color(0xFF16B8FF)
@Composable private fun LocalAuthTheme(content: @Composable () -> Unit) = MaterialTheme(
    colorScheme = darkColorScheme(primary = Violet, background = Navy, surface = Color(0xFF12182D), onBackground = Color(0xFFF3F4FF)), content = content)

@Composable private fun LockScreen(activity: FragmentActivity, lock: AppLockManager, onUnlocked: () -> Unit) {
    var setup by remember { mutableStateOf(!lock.hasPin()) }
    var pin by remember { mutableStateOf("") }
    var confirmation by remember { mutableStateOf("") }
    var error by remember { mutableStateOf<String?>(null) }
    val biometricAvailable = remember {
        BiometricManager.from(activity).canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG or BiometricManager.Authenticators.BIOMETRIC_WEAK) == BiometricManager.BIOMETRIC_SUCCESS
    }
    Box(Modifier.fillMaxSize()) {
        Image(painter = painterResource(R.drawable.localauth_landscape), contentDescription = null, contentScale = ContentScale.Crop, modifier = Modifier.fillMaxSize())
        Box(Modifier.fillMaxSize().background(Navy.copy(alpha = 0.72f)))
        Card(Modifier.align(Alignment.Center).padding(28.dp).fillMaxWidth(), colors = CardDefaults.cardColors(containerColor = Color(0xB8121A30)), border = BorderStroke(1.dp, Color(0x8020D9FF)), shape = RoundedCornerShape(26.dp)) {
            Column(Modifier.padding(26.dp), horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.spacedBy(14.dp)) {
                Icon(Icons.Default.Lock, null, tint = Color(0xFF20D9FF), modifier = Modifier.size(54.dp))
                Row { Text("Local", color = Color.White, fontSize = 28.sp, fontWeight = FontWeight.Bold); Text("Auth", color = Color(0xFF20D9FF), fontSize = 28.sp, fontWeight = FontWeight.Bold) }
                Text(if (setup) "Créez votre code de sécurité" else "Application verrouillée", color = Color(0xFFAAB3D8))
                OutlinedTextField(pin, { if (it.length <= 6 && it.all(Char::isDigit)) pin = it }, label = { Text("Code PIN à 6 chiffres") }, singleLine = true, visualTransformation = PasswordVisualTransformation(), keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword), modifier = Modifier.fillMaxWidth())
                if (setup) OutlinedTextField(confirmation, { if (it.length <= 6 && it.all(Char::isDigit)) confirmation = it }, label = { Text("Confirmer le code") }, singleLine = true, visualTransformation = PasswordVisualTransformation(), keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword), modifier = Modifier.fillMaxWidth())
                error?.let { Text(it, color = Color(0xFFFF6B6B)) }
                Button(onClick = {
                    if (setup) when { pin.length != 6 -> error = "Le code doit contenir 6 chiffres"; pin != confirmation -> error = "Les deux codes sont différents"; else -> runCatching { lock.setPin(pin.toCharArray()) }.onSuccess { setup = false; pin = ""; confirmation = ""; onUnlocked() }.onFailure { error = it.message } }
                    else if (pin.length == 6 && lock.verify(pin.toCharArray())) onUnlocked() else { error = "Code incorrect"; pin = "" }
                }, modifier = Modifier.fillMaxWidth()) { Text(if (setup) "Créer et ouvrir" else "Déverrouiller") }
                if (!setup && biometricAvailable) OutlinedButton(onClick = { showBiometric(activity, onUnlocked) { error = it } }, modifier = Modifier.fillMaxWidth()) { Icon(Icons.Default.Fingerprint, null); Spacer(Modifier.width(8.dp)); Text("Utiliser l’empreinte") }
            }
        }
    }
}

private fun showBiometric(activity: FragmentActivity, onSuccess: () -> Unit, onError: (String) -> Unit) {
    val prompt = BiometricPrompt(activity, ContextCompat.getMainExecutor(activity), object : BiometricPrompt.AuthenticationCallback() {
        override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) { onSuccess() }
        override fun onAuthenticationError(errorCode: Int, errString: CharSequence) { if (errorCode != BiometricPrompt.ERROR_USER_CANCELED && errorCode != BiometricPrompt.ERROR_NEGATIVE_BUTTON) onError(errString.toString()) }
        override fun onAuthenticationFailed() { onError("Empreinte non reconnue") }
    })
    prompt.authenticate(BiometricPrompt.PromptInfo.Builder().setTitle("Déverrouiller LocalAuth").setSubtitle("Confirmez votre empreinte digitale").setNegativeButtonText("Utiliser le code PIN").setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG or BiometricManager.Authenticators.BIOMETRIC_WEAK).build())
}

@Composable private fun Home(vm: MainViewModel) {
    val accounts by vm.accounts.collectAsState()
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var showAdd by remember { mutableStateOf(false) }
    var message by remember { mutableStateOf<String?>(null) }
    var pendingImport by remember { mutableStateOf<ByteArray?>(null) }
    var showImportPassword by remember { mutableStateOf(false) }
    var showExportPassword by remember { mutableStateOf(false) }
    var exportPassword by remember { mutableStateOf<CharArray?>(null) }
    var now by remember { mutableLongStateOf(System.currentTimeMillis()) }
    val createBackup = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/json")) { uri ->
        val password = exportPassword
        if (uri != null && password != null) scope.launch {
            runCatching { vm.exportBackup(password) }.onSuccess { bytes -> context.contentResolver.openOutputStream(uri)?.use { it.write(bytes) }; message = "Sauvegarde chiffrée créée" }.onFailure { message = "Erreur : ${it.message}" }
            exportPassword = null
        }
    }
    val openBackup = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) runCatching { context.contentResolver.openInputStream(uri)?.use { it.readBytes() } ?: error("Fichier illisible") }.onSuccess { pendingImport = it; showImportPassword = true }.onFailure { message = "Erreur : ${it.message}" }
    }
    val scanner = rememberLauncherForActivityResult(ScanContract()) { result -> result.contents?.let { vm.importQr(it) { status -> message = status } } }
    LaunchedEffect(Unit) { while (true) { now = System.currentTimeMillis(); delay(1_000) } }
    Box(Modifier.fillMaxSize()) {
        Image(painter = painterResource(R.drawable.localauth_landscape), contentDescription = null, contentScale = ContentScale.Crop, modifier = Modifier.fillMaxSize())
        Box(Modifier.fillMaxSize().background(Navy.copy(alpha = 0.58f)))
    Scaffold(containerColor = Color.Transparent, floatingActionButton = { ExtendedFloatingActionButton(onClick = { showAdd = true }, icon = { Icon(Icons.Default.Add, null) }, text = { Text("Ajouter un compte") }) }) { padding ->
        Column(Modifier.fillMaxSize().padding(padding).padding(horizontal = 18.dp)) {
            Spacer(Modifier.height(20.dp))
            Row(verticalAlignment = Alignment.CenterVertically) { Icon(Icons.Default.Lock, null, tint = Violet, modifier = Modifier.size(38.dp)); Spacer(Modifier.width(10.dp)); Column { Row { Text("Local", color = Color.White, fontSize = 29.sp, fontWeight = FontWeight.Bold); Text("Auth", color = Color(0xFF20D9FF), fontSize = 29.sp, fontWeight = FontWeight.Bold) }; Text("by souffly007 • 100 % local", color = Color(0xFFAAB3D8)) } }
            Spacer(Modifier.height(14.dp))
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                FilledTonalButton(onClick = { scanner.launch(ScanOptions().setDesiredBarcodeFormats(ScanOptions.QR_CODE).setPrompt("Scannez un QR TOTP").setBeepEnabled(false)) }, modifier = Modifier.weight(1f), contentPadding = PaddingValues(horizontal = 8.dp)) { Icon(Icons.Default.QrCodeScanner, null); Spacer(Modifier.width(4.dp)); Text("Scanner") }
                FilledTonalButton(onClick = { openBackup.launch(arrayOf("application/json", "text/plain", "*/*")) }, modifier = Modifier.weight(1f), contentPadding = PaddingValues(horizontal = 8.dp)) { Icon(Icons.Default.FileDownload, null); Spacer(Modifier.width(4.dp)); Text("Importer") }
                FilledTonalButton(onClick = { if (accounts.isEmpty()) message = "Aucun compte à sauvegarder" else showExportPassword = true }, modifier = Modifier.weight(1f), contentPadding = PaddingValues(horizontal = 8.dp)) { Icon(Icons.Default.FileUpload, null); Spacer(Modifier.width(4.dp)); Text("Exporter") }
            }
            message?.let { Text(it, color = Color(0xFF69D9FF), fontSize = 13.sp, modifier = Modifier.padding(top = 8.dp)) }
            Spacer(Modifier.height(14.dp))
            if (accounts.isEmpty()) Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) { Text("Aucun compte\nAjoutez votre première clé TOTP", color = Color(0xFFAAB3D8)) }
            else LazyColumn(verticalArrangement = Arrangement.spacedBy(12.dp), contentPadding = PaddingValues(bottom = 96.dp)) { items(accounts, key = { it.id }) { AccountCard(it, vm, now) } }
        }
    }}
    if (showAdd) AddDialog(onDismiss = { showAdd = false }) { issuer, label, secret, error -> vm.add(issuer, label, secret, error); showAdd = false }
    if (showImportPassword) PasswordDialog("Importer une sauvegarde", "Saisissez le mot de passe si l'export LocalAuth ou Proton est protégé. Laissez vide pour un JSON Proton/Aegis non chiffré.", false, onDismiss = { showImportPassword = false; pendingImport = null }) { password ->
        val bytes = pendingImport; showImportPassword = false; pendingImport = null
        if (bytes != null) vm.importFile(bytes, password) { message = it }
    }
    if (showExportPassword) PasswordDialog("Protéger la sauvegarde", "Choisissez au moins 8 caractères. Ce mot de passe sera indispensable sur le nouveau téléphone.", true, onDismiss = { showExportPassword = false }) { password ->
        showExportPassword = false; exportPassword = password; createBackup.launch("LocalAuth-backup.json")
    }
}

@Composable private fun PasswordDialog(title: String, help: String, requireConfirmation: Boolean, onDismiss: () -> Unit, onConfirm: (CharArray) -> Unit) {
    var password by remember { mutableStateOf("") }; var confirmation by remember { mutableStateOf("") }; var error by remember { mutableStateOf<String?>(null) }
    AlertDialog(onDismissRequest = onDismiss, title = { Text(title) }, text = { Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
        Text(help, color = Color(0xFFAAB3D8)); OutlinedTextField(password, { password = it }, label = { Text("Mot de passe") }, singleLine = true)
        if (requireConfirmation) OutlinedTextField(confirmation, { confirmation = it }, label = { Text("Confirmer") }, singleLine = true)
        error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
    } }, confirmButton = { Button(onClick = {
        when { requireConfirmation && password.length < 8 -> error = "8 caractères minimum"; requireConfirmation && password != confirmation -> error = "Les mots de passe sont différents"; else -> onConfirm(password.toCharArray()) }
    }) { Text("Continuer") } }, dismissButton = { TextButton(onClick = onDismiss) { Text("Annuler") } })
}

@Composable private fun AccountCard(account: Account, vm: MainViewModel, now: Long) {
    val clipboard = LocalClipboardManager.current
    val code = remember(account, now / 1000) { runCatching { Totp.code(vm.repository.secret(account), now, account.period, account.digits, account.algorithm) }.getOrDefault("••••••") }
    val remaining = account.period - ((now / 1000) % account.period).toInt()
    Card(
        colors = CardDefaults.cardColors(containerColor = Color(0x80151D36)),
        border = BorderStroke(1.dp, Color(0x8020D9FF)),
        shape = RoundedCornerShape(20.dp)
    ) {
        Column(Modifier.padding(18.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) { Column(Modifier.weight(1f)) { Text(account.issuer, color = Color(0xFF20D9FF), fontWeight = FontWeight.Bold, fontSize = 19.sp); if (account.label.isNotBlank()) Text(account.label, color = Color.White, fontSize = 13.sp) }; CountdownRing(remaining, account.period); IconButton(onClick = { vm.delete(account) }) { Icon(Icons.Default.Delete, "Supprimer", tint = Color(0xFF8D96B8)) } }
            Row(verticalAlignment = Alignment.CenterVertically) { Text(code.chunked(3).joinToString(" "), color = Color(0xFF20D9FF), fontSize = 34.sp, fontWeight = FontWeight.Bold, letterSpacing = 2.sp); Spacer(Modifier.weight(1f)); IconButton(onClick = { clipboard.setText(AnnotatedString(code)) }) { Icon(Icons.Default.ContentCopy, "Copier", tint = Color.White) } }
        }
    }
}

@Composable private fun CountdownRing(remaining: Int, period: Int) {
    val countdownColor = when {
        remaining >= 21 -> Color(0xFF66FF66)
        remaining >= 11 -> Color(0xFFFFA726)
        else -> Color(0xFFFF3D3D)
    }
    Box(Modifier.size(54.dp), contentAlignment = Alignment.Center) {
        CircularProgressIndicator(
            progress = { remaining.toFloat() / period.toFloat() },
            modifier = Modifier.fillMaxSize(),
            color = countdownColor,
            trackColor = Color(0xFF263454),
            strokeWidth = 4.dp
        )
        Text(remaining.toString().padStart(2, '0'), color = countdownColor, fontSize = 17.sp, fontWeight = FontWeight.Bold)
    }
}

@Composable private fun AddDialog(onDismiss: () -> Unit, onAdd: (String, String, String, (String) -> Unit) -> Unit) {
    var issuer by remember { mutableStateOf("") }; var label by remember { mutableStateOf("") }; var secret by remember { mutableStateOf("") }; var error by remember { mutableStateOf<String?>(null) }
    AlertDialog(onDismissRequest = onDismiss, title = { Text("Nouveau compte") }, text = { Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
        OutlinedTextField(issuer, { issuer = it }, label = { Text("Service / émetteur") }, singleLine = true)
        OutlinedTextField(label, { label = it }, label = { Text("Identifiant (facultatif)") }, singleLine = true)
        OutlinedTextField(secret, { secret = it }, label = { Text("Clé secrète Base32") }, singleLine = true)
        error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
    } }, confirmButton = { Button(onClick = { if (issuer.isBlank() || secret.isBlank()) error = "Service et clé obligatoires" else onAdd(issuer, label, secret) { error = it } }) { Text("Enregistrer") } }, dismissButton = { TextButton(onClick = onDismiss) { Text("Annuler") } })
}
