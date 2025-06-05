package org.multipaz.samples.securearea

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
import org.multipaz.securearea.SecureArea
import org.multipaz.securearea.SecureAreaRepository
import org.multipaz.securearea.cloud.CloudCreateKeySettings
import org.multipaz.securearea.cloud.CloudUserAuthType
import org.multipaz.securearea.software.SoftwareSecureArea
import org.multipaz.storage.StorageTableSpec
import org.multipaz.testapp.TestAppDocumentMetadata

object MultipazWrapper {
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

    suspend fun keyStorageInit(): Pair<EcPrivateKey, X509Cert> {

        val keyStorage = platformStorage().getTable(
            StorageTableSpec(
                name = "TestAppKeys", supportPartitions = false, supportExpiration = false
            )
        )

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
                """.trimIndent().trim(), EcCurve.P384
            )
            EcPrivateKey.fromPem(
                """
                    -----BEGIN PRIVATE KEY-----
                    MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDCcRuzXW3pW2h9W8pu5
                    /CSR6JSnfnZVATq+408WPoNC3LzXqJEQSMzPsI9U1q+wZ2yhZANiAAT5APJ7vSbY
                    7SWU9cyNWPFVnPebmTpqBP7CKH4vv1vuPKpSX32xt5SenFosP5yYHccre3CQDt+Z
                    UlKhsFz70IOGSHebHqf5igflG6VpJZOFYF8zJGOx9U4OSiwcsIOds9U=
                    -----END PRIVATE KEY-----
                """.trimIndent().trim(), iacaKeyPub
            )
        }

        val iacaKey = keyStorage.get("iacaKey")
            ?.let { EcPrivateKey.fromDataItem(Cbor.decode(it.toByteArray())) } ?: run {
            keyStorage.insert(
                "iacaKey", ByteString(Cbor.encode(bundledIacaKey.toDataItem()))
            )
            bundledIacaKey
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

        val iacaCert =
            keyStorage.get("iacaCert")?.let { X509Cert.fromDataItem(Cbor.decode(it.toByteArray())) }
                ?: run {
                    keyStorage.insert(
                        "iacaCert", ByteString(Cbor.encode(bundledIacaCert.toDataItem()))
                    )
                    bundledIacaCert
                }

        return Pair(iacaKey, iacaCert)
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
