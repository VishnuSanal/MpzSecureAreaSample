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
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import mpzsecureareasample.composeapp.generated.resources.Res
import mpzsecureareasample.composeapp.generated.resources.driving_license_card_art
import org.jetbrains.compose.ui.tooling.preview.Preview
import org.multipaz.cbor.toDataItem
import org.multipaz.compose.prompt.PromptDialogs
import org.multipaz.crypto.EcPrivateKey
import org.multipaz.crypto.X509Cert
import org.multipaz.document.DocumentStore
import org.multipaz.documenttype.DocumentAttributeType
import org.multipaz.documenttype.DocumentType
import org.multipaz.documenttype.Icon
import org.multipaz.prompt.PromptModel
import org.multipaz.samples.securearea.utils.IACAManager.keyStorageInit
import org.multipaz.samples.securearea.knowntypes.DrivingLicense.MDL_DOCTYPE
import org.multipaz.samples.securearea.knowntypes.DrivingLicense.MDL_NAMESPACE
import org.multipaz.samples.securearea.knowntypes.SampleData
import org.multipaz.samples.securearea.utils.DocumentManager.getDocumentStore
import org.multipaz.samples.securearea.utils.DocumentManager.provisionDrivingLicense

private lateinit var snackbarHostState: SnackbarHostState

private lateinit var documentStore: DocumentStore

private lateinit var iacaKey: EcPrivateKey
private lateinit var iacaCert: X509Cert

private fun showToast(message: String) {
    println("vishnu: $message")
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

            /*coroutineScope.launch(Dispatchers.Main) {
                try {
                    documentStore = getDocumentStore()
                    showToast("Document store created")
                } catch (e: Exception) {
                    e.printStackTrace()
                    showToast("Document store creation failed")
                }

                try {
                    val keyPair = keyStorageInit()

                    iacaKey = keyPair.first
                    iacaCert = keyPair.second

                    showToast("keyStorageInit done")
                } catch (e: Exception) {
                    e.printStackTrace()
                    showToast("keyStorageInit() failed")
                }

                try {
                    provisionDrivingLicense(
                        documentStore = documentStore,
                        secureArea = getPlatformSecureArea(),
                        iacaKey = iacaKey,
                        iacaCert = iacaCert,
                    )
                    showToast("Provision test documents successful")
                } catch (e: Exception) {
                    e.printStackTrace()
                    showToast("Provision test documents creation failed")
                }
            }*/

            Column(
                modifier = Modifier.fillMaxWidth().padding(50.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
            ) {

                Button(onClick = {
                    coroutineScope.launch {
                        try {
                            documentStore = getDocumentStore()
                            showToast("Document store created")
                        } catch (e: Exception) {
                            e.printStackTrace()
                            showToast("Document store creation failed")
                        }
                    }
                }) {
                    Text("Create DocumentStore")
                }

                Button(onClick = {
                    coroutineScope.launch {
                        try {
                            val keyPair = keyStorageInit()

                            iacaKey = keyPair.first
                            iacaCert = keyPair.second
                            showToast("keyStorageInit done")
                        } catch (e: Exception) {
                            e.printStackTrace()
                            showToast("keyStorageInit() failed")
                        }

                    }
                }) {
                    Text("keyStorageInit()")
                }

                Button(onClick = {
                    coroutineScope.launch {
                        try {
                            provisionDrivingLicense(
                                documentStore = documentStore,
                                secureArea = getPlatformSecureArea(),
                                iacaKey = iacaKey,
                                iacaCert = iacaCert,
                                documentType = getSimpleDocument(),
                                givenNameOverride = "Erika",
                                displayName = "Erika's Driving License",
                                cardArtResource = Res.drawable.driving_license_card_art,
                            )
                            showToast("Provision test documents successful")
                        } catch (e: Exception) {
                            e.printStackTrace()
                            showToast("Provision test documents creation failed")
                        }
                    }
                }) {
                    Text("Provision test documents")
                }
            }
        }
    }
}


private fun getSimpleDocument(): DocumentType {
    // return DrivingLicense.getDocumentType() // check this for an extensive example
    return DocumentType.Builder("Driving License")
        .addMdocDocumentType(MDL_DOCTYPE)
        .addMdocAttribute(
            DocumentAttributeType.String,
            "given_name",
            "Given Names",
            "First name(s), other name(s), or secondary identifier, of the mDL holder",
            true,
            MDL_NAMESPACE,
            Icon.PERSON,
            SampleData.GIVEN_NAME.toDataItem()
        )
        .build()
}