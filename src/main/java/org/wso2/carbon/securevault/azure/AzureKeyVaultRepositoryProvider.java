package org.wso2.carbon.securevault.azure;

import org.wso2.securevault.keystore.IdentityKeyStoreWrapper;
import org.wso2.securevault.keystore.TrustKeyStoreWrapper;
import org.wso2.securevault.secret.SecretRepository;
import org.wso2.securevault.secret.SecretRepositoryProvider;

public class AzureKeyVaultRepositoryProvider implements SecretRepositoryProvider {
    @Override
    public SecretRepository getSecretRepository(IdentityKeyStoreWrapper identityKeyStoreWrapper, TrustKeyStoreWrapper trustKeyStoreWrapper) {
        return new AzureKeyVaultRepository();
    }
}
