package org.multipaz.samples.securearea

import android.os.Build
import io.ktor.client.engine.HttpClientEngineFactory
import io.ktor.client.engine.android.Android
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.datetime.Instant
import kotlinx.io.bytestring.ByteString
import org.multipaz.context.applicationContext
import org.multipaz.crypto.Algorithm
import org.multipaz.securearea.AndroidKeystoreCreateKeySettings
import org.multipaz.securearea.AndroidKeystoreSecureArea
import org.multipaz.securearea.CreateKeySettings
import org.multipaz.securearea.SecureArea
import org.multipaz.securearea.SecureAreaProvider
import org.multipaz.securearea.UserAuthenticationType
import org.multipaz.storage.Storage
import org.multipaz.storage.android.AndroidStorage
import java.io.File
import java.net.NetworkInterface
import java.security.Security
import org.bouncycastle.jce.provider.BouncyCastleProvider

class AndroidPlatform : Platform {
    override val name: String = "Android ${Build.VERSION.SDK_INT}"
}

actual fun getPlatform(): Platform = AndroidPlatform()

private val androidStorage: AndroidStorage by lazy {
    AndroidStorage(
        File(applicationContext.dataDir.path, "storage.db").absolutePath
    )
}

actual suspend fun getPlatformSecureArea(): SecureArea {
    return AndroidKeystoreSecureArea.create(
        storage = androidStorage
    )
}

actual fun platformStorage(): Storage {
    return androidStorage
}

private val androidKeystoreSecureAreaProvider = SecureAreaProvider {
    AndroidKeystoreSecureArea.create(androidStorage)
}

actual fun platformSecureAreaProvider(): SecureAreaProvider<SecureArea> {
    return androidKeystoreSecureAreaProvider
}