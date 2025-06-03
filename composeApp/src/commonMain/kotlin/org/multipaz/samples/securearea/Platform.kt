package org.multipaz.samples.securearea

import io.ktor.client.engine.HttpClientEngineFactory
import kotlinx.datetime.Instant
import kotlinx.io.bytestring.ByteString
import org.multipaz.crypto.Algorithm
import org.multipaz.securearea.CreateKeySettings
import org.multipaz.securearea.SecureArea
import org.multipaz.securearea.SecureAreaProvider
import org.multipaz.storage.Storage

interface Platform {
    val name: String
}

expect fun getPlatform(): Platform

expect suspend fun getPlatformSecureArea(): SecureArea

expect fun getPlatformCreateKeySettings(
    challenge: ByteString,
    algorithm: Algorithm,
    userAuthenticationRequired: Boolean,
    validFrom: Instant,
    validUntil: Instant
): CreateKeySettings

expect suspend fun platformInit()

expect fun getLocalIpAddress(): String

expect val platformIsEmulator: Boolean

expect fun platformStorage(): Storage

expect fun platformHttpClientEngineFactory(): HttpClientEngineFactory<*>

/**
 * Gets a provider for the preferred [SecureArea] implementation for the platform.
 */
expect fun platformSecureAreaProvider(): SecureAreaProvider<SecureArea>

expect val platformSecureAreaHasKeyAgreement: Boolean

/**
 * Gets a [CreateKeySettings] object for creating auth-bound keys that works with the [SecureArea] returned
 * returned by [platformSecureAreaProvider].
 *
 * @param challenge the challenge to use in the generated attestation, if the [SecureArea] supports that.
 * @param curve the curve to use.
 * @param keyPurposes the key purposes
 * @param userAuthenticationRequired set to `true` to require user authentication, `false` otherwise.
 * @param validFrom when the key should be valid from.
 * @param validUntil when the key should be valid until.
 */
expect fun platformCreateKeySettings(
    challenge: ByteString,
    algorithm: Algorithm,
    userAuthenticationRequired: Boolean,
    validFrom: Instant,
    validUntil: Instant
): CreateKeySettings
