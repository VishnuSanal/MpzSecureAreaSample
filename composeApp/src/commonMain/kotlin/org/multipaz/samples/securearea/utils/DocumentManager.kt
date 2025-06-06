package org.multipaz.samples.securearea.utils

import androidx.compose.ui.graphics.ImageBitmap
import org.jetbrains.compose.resources.DrawableResource
import org.multipaz.credential.Credential
import org.multipaz.credential.CredentialLoader
import org.multipaz.credential.SecureAreaBoundCredential
import org.multipaz.crypto.Algorithm
import org.multipaz.crypto.EcPrivateKey
import org.multipaz.crypto.X509Cert
import org.multipaz.document.Document
import org.multipaz.document.DocumentStore
import org.multipaz.documenttype.DocumentType
import org.multipaz.samples.securearea.MultipazUtils.generateDsKeyAndCert
import org.multipaz.samples.securearea.MultipazUtils.provisionDocument
import org.multipaz.samples.securearea.platformSecureAreaProvider
import org.multipaz.samples.securearea.platformStorage
import org.multipaz.securearea.KeyInfo
import org.multipaz.securearea.SecureArea
import org.multipaz.securearea.SecureAreaRepository
import org.multipaz.securearea.cloud.CloudCreateKeySettings
import org.multipaz.securearea.cloud.CloudUserAuthType
import org.multipaz.securearea.software.SoftwareSecureArea
import org.multipaz.testapp.TestAppDocumentMetadata

object DocumentManager {
    suspend fun getDocumentStore(): DocumentStore {
        return DocumentStore(
            storage = platformStorage(),
            secureAreaRepository = SecureAreaRepository.build {
                add(SoftwareSecureArea.create(platformStorage()))
                add(platformSecureAreaProvider().get())
            },
            credentialLoader = CredentialLoader(),
            documentMetadataFactory = TestAppDocumentMetadata::create
        )
    }

    suspend fun provisionDrivingLicense(
        documentStore: DocumentStore,
        secureArea: SecureArea,
        documentType: DocumentType,
        givenNameOverride: String,
        displayName: String,
        cardArtResource: DrawableResource,
        iacaKey: EcPrivateKey,
        iacaCert: X509Cert,
    ) {
        val (dsKey, dsCert) = generateDsKeyAndCert(
            Algorithm.ESP256,
            iacaKey, iacaCert
        )
        provisionDocument(
            documentStore = documentStore,
            secureArea = secureArea,
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
            documentType = documentType,
            deviceKeyAlgorithm = Algorithm.ESP256,
            deviceKeyMacAlgorithm = Algorithm.ESP256,
            numCredentialsPerDomain = 2,
            givenNameOverride = givenNameOverride,
            displayName = displayName,
            cardArtResource = cardArtResource
        )
    }
}

data class DocumentInfo(
    val document: Document,
    val cardArt: ImageBitmap? = null,
    val credentialInfos: List<CredentialInfo>
)

data class CredentialInfo(
    val credential: Credential,
    val keyInfo: KeyInfo?,
    val keyInvalidated: Boolean
)

suspend fun Document.buildCredentialInfos(): List<CredentialInfo> {
    return getCredentials().map { credential ->
        val keyInfo = if (credential is SecureAreaBoundCredential) {
            credential.secureArea.getKeyInfo(credential.alias)
        } else {
            null
        }
        val keyInvalidated = if (credential is SecureAreaBoundCredential) {
            credential.secureArea.getKeyInvalidated(credential.alias)
        } else {
            false
        }
        CredentialInfo(
            credential = credential,
            keyInfo = keyInfo,
            keyInvalidated = keyInvalidated
        )
    }
}