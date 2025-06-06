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

expect fun platformStorage(): Storage

/**
 * Gets a provider for the preferred [SecureArea] implementation for the platform.
 */
expect fun platformSecureAreaProvider(): SecureAreaProvider<SecureArea>
