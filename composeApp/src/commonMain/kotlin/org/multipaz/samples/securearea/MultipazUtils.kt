package org.multipaz.samples.securearea

import kotlinx.datetime.Clock
import kotlinx.datetime.Instant
import kotlinx.io.bytestring.ByteString
import kotlinx.io.bytestring.encodeToByteString
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import mpzsecureareasample.composeapp.generated.resources.Res
import mpzsecureareasample.composeapp.generated.resources.driving_license_card_art
import org.jetbrains.compose.resources.DrawableResource
import org.jetbrains.compose.resources.ExperimentalResourceApi
import org.jetbrains.compose.resources.getDrawableResourceBytes
import org.jetbrains.compose.resources.getSystemResourceEnvironment
import org.multipaz.cbor.Bstr
import org.multipaz.cbor.Cbor
import org.multipaz.cbor.DataItem
import org.multipaz.cbor.RawCbor
import org.multipaz.cbor.Tagged
import org.multipaz.cbor.Tstr
import org.multipaz.cbor.buildCborMap
import org.multipaz.cbor.toDataItem
import org.multipaz.cose.Cose
import org.multipaz.cose.CoseLabel
import org.multipaz.cose.CoseNumberLabel
import org.multipaz.credential.SecureAreaBoundCredential
import org.multipaz.crypto.Algorithm
import org.multipaz.crypto.EcPrivateKey
import org.multipaz.crypto.X509Cert
import org.multipaz.crypto.X509CertChain
import org.multipaz.document.Document
import org.multipaz.document.DocumentStore
import org.multipaz.documenttype.DocumentType
import org.multipaz.mdoc.credential.MdocCredential
import org.multipaz.mdoc.issuersigned.buildIssuerNamespaces
import org.multipaz.mdoc.mso.MobileSecurityObjectGenerator
import org.multipaz.samples.securearea.knowntypes.DrivingLicense
import org.multipaz.sdjwt.Issuer
import org.multipaz.sdjwt.SdJwtVcGenerator
import org.multipaz.sdjwt.credential.KeyBoundSdJwtVcCredential
import org.multipaz.sdjwt.credential.KeylessSdJwtVcCredential
import org.multipaz.sdjwt.util.JsonWebKey
import org.multipaz.securearea.CreateKeySettings
import org.multipaz.securearea.SecureArea
import org.multipaz.testapp.TestAppDocumentMetadata
import org.multipaz.util.Logger
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.hours

object MultipazUtils {

    // This domain is for MdocCredential using mdoc ECDSA/EdDSA authentication and requiring user authentication.
    const val CREDENTIAL_DOMAIN_MDOC_USER_AUTH = "mdoc_user_auth"

    // This domain is for MdocCredential using mdoc ECDSA/EdDSA authentication and not requiring user authentication.
    const val CREDENTIAL_DOMAIN_MDOC_NO_USER_AUTH = "mdoc_no_user_auth"

    // This domain is for MdocCredential using mdoc MAC authentication and requiring user authentication.
    const val CREDENTIAL_DOMAIN_MDOC_MAC_USER_AUTH = "mdoc_mac_user_auth"

    // This domain is for MdocCredential using mdoc MAC authentication and not requiring user authentication.
    const val CREDENTIAL_DOMAIN_MDOC_MAC_NO_USER_AUTH = "mdoc_mac_no_user_auth"

    // This domain is for KeyBoundSdJwtVcCredential and requiring user authentication.
    const val CREDENTIAL_DOMAIN_SDJWT_USER_AUTH = "sdjwt_user_auth"

    // This domain is for KeyBoundSdJwtVcCredential and not requiring user authentication.
    const val CREDENTIAL_DOMAIN_SDJWT_NO_USER_AUTH = "sdjwt_no_user_auth"

    // This domain is for KeylessSdJwtVcCredential
    const val CREDENTIAL_DOMAIN_SDJWT_KEYLESS = "sdjwt_keyless"

    suspend fun provisionTestDocuments(
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
    ) {
        require(deviceKeyAlgorithm.isSigning)
//        require(deviceKeyMacAlgorithm == Algorithm.UNSET || deviceKeyMacAlgorithm.isKeyAgreement)
        provisionDocument(
            documentStore,
            secureArea,
            secureAreaCreateKeySettingsFunc,
            dsKey,
            dsCert,
            deviceKeyAlgorithm,
            deviceKeyMacAlgorithm,
            numCredentialsPerDomain,
            DrivingLicense.getDocumentType(),
            "Erika",
            "Erika's Driving License",
            Res.drawable.driving_license_card_art
        )
    }

    @OptIn(ExperimentalResourceApi::class)
    private suspend fun provisionDocument(
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
        documentType: DocumentType,
        givenNameOverride: String,
        displayName: String,
        cardArtResource: DrawableResource,
    ) {
        val cardArt = getDrawableResourceBytes(
            getSystemResourceEnvironment(),
            cardArtResource,
        )

        val document = documentStore.createDocument {
            val metadata = it as TestAppDocumentMetadata
            metadata.initialize(
                displayName = displayName,
                typeDisplayName = documentType.displayName,
                cardArt = ByteString(cardArt),
            )
        }

        val now = Clock.System.now()
        val signedAt = now - 1.hours
        val validFrom = now - 1.hours
        val validUntil = now + 365.days

        if (documentType.mdocDocumentType != null) {
            addMdocCredentials(
                document = document,
                documentType = documentType,
                secureArea = secureArea,
                secureAreaCreateKeySettingsFunc = secureAreaCreateKeySettingsFunc,
                deviceKeyAlgorithm = deviceKeyAlgorithm,
                deviceKeyMacAlgorithm = deviceKeyMacAlgorithm,
                signedAt = signedAt,
                validFrom = validFrom,
                validUntil = validUntil,
                dsKey = dsKey,
                dsCert = dsCert,
                numCredentialsPerDomain = numCredentialsPerDomain,
                givenNameOverride = givenNameOverride
            )
        }

        if (documentType.vcDocumentType != null) {
            addSdJwtVcCredentials(
                document = document,
                documentType = documentType,
                secureArea = secureArea,
                secureAreaCreateKeySettingsFunc = secureAreaCreateKeySettingsFunc,
                deviceKeyAlgorithm = deviceKeyAlgorithm,
                signedAt = signedAt,
                validFrom = validFrom,
                validUntil = validUntil,
                dsKey = dsKey,
                dsCert = dsCert,
                numCredentialsPerDomain = numCredentialsPerDomain,
                givenNameOverride = givenNameOverride
            )
        }
    }

    private suspend fun addMdocCredentials(
        document: Document,
        documentType: DocumentType,
        secureArea: SecureArea,
        secureAreaCreateKeySettingsFunc: (
            challenge: ByteString,
            algorithm: Algorithm,
            userAuthenticationRequired: Boolean,
            validFrom: Instant,
            validUntil: Instant
        ) -> CreateKeySettings,
        deviceKeyAlgorithm: Algorithm,
        deviceKeyMacAlgorithm: Algorithm,
        signedAt: Instant,
        validFrom: Instant,
        validUntil: Instant,
        dsKey: EcPrivateKey,
        dsCert: X509Cert,
        numCredentialsPerDomain: Int,
        givenNameOverride: String
    ) {
        val issuerNamespaces = buildIssuerNamespaces {
            for ((nsName, ns) in documentType.mdocDocumentType?.namespaces!!) {
                addNamespace(nsName) {
                    for ((deName, de) in ns.dataElements) {
                        val sampleValue = de.attribute.sampleValueMdoc
                        if (sampleValue != null) {
                            val value = if (deName.startsWith("given_name")) {
                                Tstr(givenNameOverride)
                            } else {
                                sampleValue
                            }
                            addDataElement(deName, value)
                        } else {
                            Logger.w("vishnu", "No sample value for data element $deName")
                        }
                    }
                }
            }
        }

        // Create authentication keys...
        for (domain in listOf(
            CREDENTIAL_DOMAIN_MDOC_USER_AUTH,
            CREDENTIAL_DOMAIN_MDOC_NO_USER_AUTH,
            CREDENTIAL_DOMAIN_MDOC_MAC_USER_AUTH,
            CREDENTIAL_DOMAIN_MDOC_MAC_NO_USER_AUTH
        )) {
            val userAuthenticationRequired = when (domain) {
                CREDENTIAL_DOMAIN_MDOC_USER_AUTH, CREDENTIAL_DOMAIN_MDOC_MAC_USER_AUTH -> true
                else -> false
            }
            val algorithm = when (domain) {
                CREDENTIAL_DOMAIN_MDOC_USER_AUTH -> deviceKeyAlgorithm
                CREDENTIAL_DOMAIN_MDOC_NO_USER_AUTH -> deviceKeyAlgorithm
                CREDENTIAL_DOMAIN_MDOC_MAC_USER_AUTH -> deviceKeyMacAlgorithm
                CREDENTIAL_DOMAIN_MDOC_MAC_NO_USER_AUTH ->  deviceKeyMacAlgorithm
                else -> throw IllegalStateException()
            }
            if (algorithm == Algorithm.UNSET) {
                continue
            }

            for (n in 1..numCredentialsPerDomain) {
                val mdocCredential = MdocCredential.create(
                    document = document,
                    asReplacementForIdentifier = null,
                    domain = domain,
                    secureArea = secureArea,
                    docType = documentType.mdocDocumentType!!.docType,
                    createKeySettings = secureAreaCreateKeySettingsFunc(
                        "Challenge".encodeToByteString(),
                        algorithm,
                        userAuthenticationRequired,
                        validFrom,
                        validUntil
                    )
                )

                // Generate an MSO and issuer-signed data for this authentication key.
                val msoGenerator = MobileSecurityObjectGenerator(
                    Algorithm.SHA256,
                    documentType.mdocDocumentType!!.docType,
                    mdocCredential.getAttestation().publicKey
                )
                msoGenerator.setValidityInfo(signedAt, validFrom, validUntil, null)
                msoGenerator.addValueDigests(issuerNamespaces)

                val mso = msoGenerator.generate()
                val taggedEncodedMso = Cbor.encode(Tagged(24, Bstr(mso)))

                // IssuerAuth is a COSE_Sign1 where payload is MobileSecurityObjectBytes
                //
                // MobileSecurityObjectBytes = #6.24(bstr .cbor MobileSecurityObject)
                //
                val protectedHeaders = mapOf<CoseLabel, DataItem>(
                    Pair(
                        CoseNumberLabel(Cose.COSE_LABEL_ALG),
                        Algorithm.ES256.coseAlgorithmIdentifier!!.toDataItem()
                    )
                )
                val unprotectedHeaders = mapOf<CoseLabel, DataItem>(
                    Pair(
                        CoseNumberLabel(Cose.COSE_LABEL_X5CHAIN),
                        X509CertChain(listOf(dsCert)).toDataItem()
                    )
                )
                val encodedIssuerAuth = Cbor.encode(
                    Cose.coseSign1Sign(
                        dsKey,
                        taggedEncodedMso,
                        true,
                        dsKey.publicKey.curve.defaultSigningAlgorithm,
                        protectedHeaders,
                        unprotectedHeaders
                    ).toDataItem()
                )
                val issuerProvidedAuthenticationData = Cbor.encode(
                    buildCborMap {
                        put("nameSpaces", issuerNamespaces.toDataItem())
                        put("issuerAuth", RawCbor(encodedIssuerAuth))
                    }
                )

                // Now that we have issuer-provided authentication data we certify the authentication key.
                mdocCredential.certify(
                    issuerProvidedAuthenticationData,
                    validFrom,
                    validUntil
                )
            }
        }

    }

    // Technically - according to RFC 7800 at least - SD-JWT could do MACing too but it would
    // need to be specced out in e.g. SD-JWT VC profile where to get the public key from the
    // recipient. So for now, we only support signing.
    //
    private suspend fun addSdJwtVcCredentials(
        document: Document,
        documentType: DocumentType,
        secureArea: SecureArea,
        secureAreaCreateKeySettingsFunc: (
            challenge: ByteString,
            algorithm: Algorithm,
            userAuthenticationRequired: Boolean,
            validFrom: Instant,
            validUntil: Instant
        ) -> CreateKeySettings,
        deviceKeyAlgorithm: Algorithm,
        signedAt: Instant,
        validFrom: Instant,
        validUntil: Instant,
        dsKey: EcPrivateKey,
        dsCert: X509Cert,
        numCredentialsPerDomain: Int,
        givenNameOverride: String
    ) {
        if (documentType.vcDocumentType == null) {
            return
        }

        val identityAttributes = buildJsonObject {
            for ((claimName, attribute) in documentType.vcDocumentType!!.claims) {
                val sampleValue = attribute.sampleValueVc
                if (sampleValue != null) {
                    val value = if (claimName.startsWith("given_name")) {
                        JsonPrimitive(givenNameOverride)
                    } else {
                        sampleValue
                    }
                    put(claimName, value)
                } else {
                    Logger.w("vishnu", "No sample value for claim $claimName")
                }
            }
        }

        val (domains, numCredentialsPerDomainAdj) = if (documentType.vcDocumentType!!.keyBound) {
            Pair(listOf(CREDENTIAL_DOMAIN_SDJWT_USER_AUTH, CREDENTIAL_DOMAIN_SDJWT_NO_USER_AUTH), numCredentialsPerDomain)
        } else {
            // No point in having multiple credentials for keyless credentials..
            Pair(listOf(CREDENTIAL_DOMAIN_SDJWT_KEYLESS), 1)
        }
        for (domain in domains) {
            for (n in 1..numCredentialsPerDomainAdj) {
                val credential = if (documentType.vcDocumentType!!.keyBound) {
                    val userAuthenticationRequired = (domain == CREDENTIAL_DOMAIN_SDJWT_USER_AUTH)
                    KeyBoundSdJwtVcCredential.create(
                        document = document,
                        asReplacementForIdentifier = null,
                        domain = domain,
                        secureArea = secureArea,
                        vct = documentType.vcDocumentType!!.type,
                        createKeySettings = secureAreaCreateKeySettingsFunc(
                            "Challenge".encodeToByteString(),
                            deviceKeyAlgorithm,
                            userAuthenticationRequired,
                            validFrom,
                            validUntil
                        )
                    )
                } else {
                    KeylessSdJwtVcCredential.create(
                        document = document,
                        asReplacementForIdentifier = null,
                        domain = domain,
                        vct = documentType.vcDocumentType!!.type,
                    )
                }

                val sdJwtVcGenerator = SdJwtVcGenerator(
                    vct = credential.vct,
                    payload = identityAttributes,
                    issuer = Issuer(
                        "https://example-issuer.com",
                        dsKey.publicKey.curve.defaultSigningAlgorithmFullySpecified,
                        null,
                    ),
                )
                sdJwtVcGenerator.publicKey =
                    (credential as? SecureAreaBoundCredential)?.let { JsonWebKey(it.getAttestation().publicKey) }
                sdJwtVcGenerator.timeSigned = signedAt
                sdJwtVcGenerator.timeValidityBegin = validFrom
                sdJwtVcGenerator.timeValidityEnd = validUntil
                val sdJwt = sdJwtVcGenerator.generateSdJwt(dsKey)
                credential.certify(
                    sdJwt.toString().encodeToByteArray(),
                    validFrom,
                    validUntil
                )
            }
        }
    }

}

