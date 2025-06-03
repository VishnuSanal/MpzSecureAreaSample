package org.multipaz.samples.securearea

import org.multipaz.credential.CredentialLoader
import org.multipaz.document.DocumentStore
import org.multipaz.securearea.SecureAreaRepository
import org.multipaz.securearea.software.SoftwareSecureArea
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
}
