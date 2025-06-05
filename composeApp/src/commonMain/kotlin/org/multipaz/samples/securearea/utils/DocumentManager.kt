package org.multipaz.samples.securearea.utils

import kotlinx.datetime.LocalDate
import kotlinx.datetime.TimeZone
import kotlinx.datetime.atStartOfDayIn
import kotlinx.io.bytestring.ByteString
import org.jetbrains.compose.resources.DrawableResource
import org.multipaz.asn1.ASN1Integer
import org.multipaz.cbor.Cbor
import org.multipaz.credential.CredentialLoader
import org.multipaz.crypto.Algorithm
import org.multipaz.crypto.EcCurve
import org.multipaz.crypto.EcPrivateKey
import org.multipaz.crypto.EcPublicKey
import org.multipaz.crypto.X500Name
import org.multipaz.crypto.X509Cert
import org.multipaz.document.DocumentStore
import org.multipaz.documenttype.DocumentType
import org.multipaz.mdoc.util.MdocUtil
import org.multipaz.samples.securearea.MultipazUtils.generateDsKeyAndCert
import org.multipaz.samples.securearea.MultipazUtils.provisionDocument
import org.multipaz.samples.securearea.platformSecureAreaProvider
import org.multipaz.samples.securearea.platformStorage
import org.multipaz.securearea.SecureArea
import org.multipaz.securearea.SecureAreaRepository
import org.multipaz.securearea.cloud.CloudCreateKeySettings
import org.multipaz.securearea.cloud.CloudUserAuthType
import org.multipaz.securearea.software.SoftwareSecureArea
import org.multipaz.storage.StorageTableSpec
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
