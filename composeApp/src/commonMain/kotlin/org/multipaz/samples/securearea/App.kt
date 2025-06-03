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
import kotlinx.datetime.Clock
import kotlinx.datetime.Instant
import kotlinx.datetime.LocalDate
import kotlinx.datetime.TimeZone
import kotlinx.datetime.atStartOfDayIn
import kotlinx.io.bytestring.ByteString
import org.jetbrains.compose.ui.tooling.preview.Preview
import org.multipaz.asn1.ASN1Integer
import org.multipaz.cbor.Cbor
import org.multipaz.compose.prompt.PromptDialogs
import org.multipaz.crypto.Algorithm
import org.multipaz.crypto.Crypto
import org.multipaz.crypto.EcCurve
import org.multipaz.crypto.EcPrivateKey
import org.multipaz.crypto.EcPublicKey
import org.multipaz.crypto.X500Name
import org.multipaz.crypto.X509Cert
import org.multipaz.document.DocumentStore
import org.multipaz.documenttype.DocumentTypeRepository
import org.multipaz.mdoc.util.MdocUtil
import org.multipaz.prompt.PromptModel
import org.multipaz.samples.securearea.MultipazWrapper.getDocumentStore
import org.multipaz.securearea.CreateKeySettings
import org.multipaz.securearea.SecureArea
import org.multipaz.securearea.SecureAreaRepository
import org.multipaz.securearea.cloud.CloudCreateKeySettings
import org.multipaz.securearea.cloud.CloudUserAuthType
import org.multipaz.securearea.software.SoftwareSecureArea
import org.multipaz.storage.StorageTable
import org.multipaz.storage.StorageTableSpec
import org.multipaz.storage.base.BaseStorageTable
import org.multipaz.trustmanagement.TrustManager
import kotlin.time.Duration.Companion.days

private lateinit var snackbarHostState: SnackbarHostState

lateinit var documentTypeRepository: DocumentTypeRepository

lateinit var secureAreaRepository: SecureAreaRepository
lateinit var softwareSecureArea: SoftwareSecureArea
lateinit var documentStore: DocumentStore

lateinit var iacaKey: EcPrivateKey
lateinit var iacaCert: X509Cert

lateinit var readerRootKey: EcPrivateKey
lateinit var readerRootCert: X509Cert

lateinit var readerKey: EcPrivateKey
lateinit var readerCert: X509Cert

lateinit var issuerTrustManager: TrustManager

lateinit var readerTrustManager: TrustManager

private lateinit var keyStorage: StorageTable

private val testDocumentTableSpec = object : StorageTableSpec(
    name = "TestAppDocuments",
    supportExpiration = false,
    supportPartitions = false,
    schemaVersion = 1L, // Bump every time incompatible changes are made
) {
    override suspend fun schemaUpgrade(oldTable: BaseStorageTable) {
        oldTable.deleteAll()
    }
}

private suspend fun keyStorageInit() {

    val certsValidFrom = LocalDate.parse("2024-12-01").atStartOfDayIn(TimeZone.UTC)
    val certsValidUntil = LocalDate.parse("2034-12-01").atStartOfDayIn(TimeZone.UTC)

    val bundledIacaKey: EcPrivateKey by lazy {
        val iacaKeyPub = EcPublicKey.fromPem(
            """
                    -----BEGIN PUBLIC KEY-----
                    MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE+QDye70m2O0llPXMjVjxVZz3m5k6agT+
                    wih+L79b7jyqUl99sbeUnpxaLD+cmB3HK3twkA7fmVJSobBc+9CDhkh3mx6n+YoH
                    5RulaSWThWBfMyRjsfVODkosHLCDnbPV
                    -----END PUBLIC KEY-----
                """.trimIndent().trim(),
            EcCurve.P384
        )
        EcPrivateKey.fromPem(
            """
                    -----BEGIN PRIVATE KEY-----
                    MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDCcRuzXW3pW2h9W8pu5
                    /CSR6JSnfnZVATq+408WPoNC3LzXqJEQSMzPsI9U1q+wZ2yhZANiAAT5APJ7vSbY
                    7SWU9cyNWPFVnPebmTpqBP7CKH4vv1vuPKpSX32xt5SenFosP5yYHccre3CQDt+Z
                    UlKhsFz70IOGSHebHqf5igflG6VpJZOFYF8zJGOx9U4OSiwcsIOds9U=
                    -----END PRIVATE KEY-----
                """.trimIndent().trim(),
            iacaKeyPub
        )
    }

    val bundledIacaCert: X509Cert by lazy {
        MdocUtil.generateIacaCertificate(
            iacaKey = iacaKey,
            subject = X500Name.fromName("C=US,CN=OWF Multipaz TEST IACA"),
            serial = ASN1Integer.fromRandom(numBits = 128),
            validFrom = certsValidFrom,
            validUntil = certsValidUntil,
            issuerAltNameUrl = "https://github.com/openwallet-foundation-labs/identity-credential",
            crlUrl = "https://github.com/openwallet-foundation-labs/identity-credential/crl"
        )
    }

    keyStorage = platformStorage().getTable(
        StorageTableSpec(
            name = "TestAppKeys",
            supportPartitions = false,
            supportExpiration = false
        )
    )

    iacaKey =
        keyStorage.get("iacaKey")?.let { EcPrivateKey.fromDataItem(Cbor.decode(it.toByteArray())) }
            ?: run {
                keyStorage.insert("iacaKey", ByteString(Cbor.encode(bundledIacaKey.toDataItem())))
                bundledIacaKey
            }
    iacaCert =
        keyStorage.get("iacaCert")?.let { X509Cert.fromDataItem(Cbor.decode(it.toByteArray())) }
            ?: run {
                keyStorage.insert("iacaCert", ByteString(Cbor.encode(bundledIacaCert.toDataItem())))
                bundledIacaCert
            }
}


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

            coroutineScope.launch(Dispatchers.Main) {
                try {
                    documentStore = getDocumentStore()
                    showToast("Document store created")
                } catch (e: Exception) {
                    e.printStackTrace()
                    showToast("Document store creation failed")
                }

                try {
                    keyStorageInit()

                    showToast("keyStorageInit done")
                } catch (e: Exception) {
                    e.printStackTrace()
                    showToast("keyStorageInit() failed")
                }

                try {
                    val (dsKey, dsCert) = generateDsKeyAndCert(
                        Algorithm.ESP256, // hardcoded
                        iacaKey, iacaCert
                    )
                    provisionTestDocuments(
                        documentStore = documentStore,
                        secureArea = getPlatformSecureArea(),
                        secureAreaCreateKeySettingsFunc = { challenge, algorithm, userAuthenticationRequired, validFrom, validUntil ->
                            CloudCreateKeySettings.Builder(challenge)
                                .setAlgorithm(algorithm).setPassphraseRequired(true)
                                .setUserAuthenticationRequired(
                                    userAuthenticationRequired, setOf(
                                        CloudUserAuthType.PASSCODE,
                                        CloudUserAuthType.BIOMETRIC
                                    )
                                ).setValidityPeriod(validFrom, validUntil).build()
                        },
                        dsKey = dsKey,
                        dsCert = dsCert,
                        showToast = { message: String -> showToast(message) },
                        deviceKeyAlgorithm = Algorithm.ESP256, // hardcoded
                        deviceKeyMacAlgorithm = Algorithm.ESP256, // hardcoded
                        numCredentialsPerDomain = 2, // hardcoded
                    )
                    showToast("Provision test documents successful")
                } catch (e: Exception) {
                    e.printStackTrace()
                    showToast("Provision test documents creation failed")
                }
            }

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
                            keyStorageInit()
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
                            val (dsKey, dsCert) = generateDsKeyAndCert(
                                Algorithm.ESP256, // hardcoded
                                iacaKey, iacaCert
                            )
                            provisionTestDocuments(
                                documentStore = documentStore,
                                secureArea = getPlatformSecureArea(),
                                secureAreaCreateKeySettingsFunc = { challenge, algorithm, userAuthenticationRequired, validFrom, validUntil ->
                                    CloudCreateKeySettings.Builder(challenge)
                                        .setAlgorithm(algorithm).setPassphraseRequired(true)
                                        .setUserAuthenticationRequired(
                                            userAuthenticationRequired, setOf(
                                                CloudUserAuthType.PASSCODE,
                                                CloudUserAuthType.BIOMETRIC
                                            )
                                        ).setValidityPeriod(validFrom, validUntil).build()
                                },
                                dsKey = dsKey,
                                dsCert = dsCert,
                                showToast = { message: String -> showToast(message) },
                                deviceKeyAlgorithm = Algorithm.ESP256, // hardcoded
                                deviceKeyMacAlgorithm = Algorithm.ESP256, // hardcoded
                                numCredentialsPerDomain = 2, // hardcoded
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

private suspend fun provisionTestDocuments(
    documentStore: DocumentStore,
    secureArea: SecureArea,
    secureAreaCreateKeySettingsFunc: (
        challenge: ByteString, algorithm: Algorithm, userAuthenticationRequired: Boolean, validFrom: Instant, validUntil: Instant
    ) -> CreateKeySettings,
    dsKey: EcPrivateKey,
    dsCert: X509Cert,
    deviceKeyAlgorithm: Algorithm,
    deviceKeyMacAlgorithm: Algorithm,
    numCredentialsPerDomain: Int,
    showToast: (message: String) -> Unit,
) {
    if (secureArea.supportedAlgorithms.find { it == deviceKeyAlgorithm } == null) {
        showToast("Secure Area doesn't support algorithm $deviceKeyAlgorithm for DeviceKey")
        return
    }
    if (deviceKeyMacAlgorithm != Algorithm.UNSET && secureArea.supportedAlgorithms.find { it == deviceKeyMacAlgorithm } == null) {
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
}

private fun generateDsKeyAndCert(
    algorithm: Algorithm,
    iacaKey: EcPrivateKey,
    iacaCert: X509Cert,
): Pair<EcPrivateKey, X509Cert> {
    // The DS cert must not be valid for more than 457 days.
    //
    // Reference: ISO/IEC 18013-5:2021 Annex B.1.4 Document signer certificate
    //
    val dsCertValidFrom = Clock.System.now() - 1.days
    val dsCertsValidUntil = dsCertValidFrom + 455.days
    val dsKey = Crypto.createEcPrivateKey(algorithm.curve!!)
    val dsCert = MdocUtil.generateDsCertificate(
        iacaCert = iacaCert,
        iacaKey = iacaKey,
        dsKey = dsKey.publicKey,
        subject = X500Name.fromName("C=US,CN=OWF Multipaz TEST DS"),
        serial = ASN1Integer.fromRandom(numBits = 128),
        validFrom = dsCertValidFrom,
        validUntil = dsCertsValidUntil,
    )
    return Pair(dsKey, dsCert)
}