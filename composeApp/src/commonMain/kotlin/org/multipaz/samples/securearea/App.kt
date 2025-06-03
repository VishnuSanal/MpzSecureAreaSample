package org.multipaz.samples.securearea

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material.Button
import androidx.compose.material.MaterialTheme
import androidx.compose.material.Scaffold
import androidx.compose.material.SnackbarDuration
import androidx.compose.material.SnackbarHost
import androidx.compose.material.SnackbarHostState
import androidx.compose.material.SnackbarResult
import androidx.compose.material.Text
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.datetime.Clock
import kotlinx.datetime.Instant
import kotlinx.io.bytestring.ByteString
import org.jetbrains.compose.ui.tooling.preview.Preview
import org.multipaz.crypto.Algorithm
import org.multipaz.prompt.PromptModel
import org.multipaz.compose.prompt.PromptDialogs
import org.multipaz.crypto.EcPrivateKey
import org.multipaz.crypto.X509Cert
import org.multipaz.document.DocumentStore
import org.multipaz.securearea.CreateKeySettings
import org.multipaz.securearea.SecureArea
import kotlin.time.Duration.Companion.days

private lateinit var snackbarHostState: SnackbarHostState

private fun showToast(message: String) {
    CoroutineScope(Dispatchers.Main).launch {
        when (snackbarHostState.showSnackbar(
            message = message,
            actionLabel = "OK",
            duration = SnackbarDuration.Short,
        )) {
            SnackbarResult.Dismissed -> {
            }

            SnackbarResult.ActionPerformed -> {
            }
        }
    }
}

@Composable
@Preview
fun App(promptModel: PromptModel) {

    snackbarHostState = remember { SnackbarHostState() }
    MaterialTheme {
        Scaffold(
            snackbarHost = { SnackbarHost(hostState = snackbarHostState) },
        ) { innerPadding ->

            PromptDialogs(promptModel)

            val coroutineScope = rememberCoroutineScope { promptModel }

            var showContent by remember { mutableStateOf(false) }
            Column(
                modifier = Modifier.fillMaxWidth().padding(50.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
            ) {
                Button(onClick = {
                    showContent = !showContent
                    coroutineScope.launch {
                        try {
                            val secureArea = getPlatformSecureArea()
                            val now = Clock.System.now()
                            val createKeySettings = getPlatformCreateKeySettings(
                                challenge = ByteString(1, 2, 3),
                                algorithm = Algorithm.ESP256,
                                userAuthenticationRequired = true,
                                validFrom = now,
                                validUntil = now + 1.days
                            )
                            secureArea.createKey("testKey", createKeySettings)
                            val signature = secureArea.sign(
                                alias = "testKey",
                                dataToSign = byteArrayOf(1, 2, 3),
                            )
                            showToast("Signed data using ${secureArea.identifier}")
                        } catch (e: Throwable) {
                            showToast("Error signing data: $e")
                        }
                    }
                }) {
                    Text("Click me!")
                }
            }
        }
    }
}

private suspend fun provisionTestDocuments(
    documentStore: DocumentStore,
    secureArea: SecureArea,
    secureAreaCreateKeySettingsFunc: (
        challenge: ByteString,
        algorithm: Algorithm,
        userAuthenticationRequired: Boolean,
        validFrom: Instant,
        validUntil: Instant
    ) -> CreateKeySettings,
    dsKey: EcPrivateKey,
    dsCert: X509Cert,
    deviceKeyAlgorithm: Algorithm,
    deviceKeyMacAlgorithm: Algorithm,
    numCredentialsPerDomain: Int,
    showToast: (message: String) -> Unit,
    showDocumentCreationDialog: MutableState<Boolean>
) {
    // This can be slow... so we show a dialog to help convey this to the user.
    showDocumentCreationDialog.value = true

    if (documentStore.listDocuments().size >= 5) {
        // TODO: we need a more granular check once we support provisioning other kinds of documents
        showToast("Test Documents already provisioned. Delete all documents and try again")
        return
    }
    if (secureArea.supportedAlgorithms.find { it == deviceKeyAlgorithm } == null) {
        showToast("Secure Area doesn't support algorithm $deviceKeyAlgorithm for DeviceKey")
        return
    }
    if (deviceKeyMacAlgorithm != Algorithm.UNSET &&
        secureArea.supportedAlgorithms.find { it == deviceKeyMacAlgorithm } == null) {
        showToast("Secure Area doesn't support algorithm $deviceKeyMacAlgorithm for DeviceKey for MAC")
        return
    }
    try {
        MultipazUtils.provisionTestDocuments(
            documentStore,
            secureArea,
            secureAreaCreateKeySettingsFunc,
            dsKey,
            dsCert,
            deviceKeyAlgorithm,
            deviceKeyMacAlgorithm,
            numCredentialsPerDomain
        )
    } catch (e: Throwable) {
        e.printStackTrace()
        showToast("Error provisioning documents: $e")
    }
    showDocumentCreationDialog.value = false
}