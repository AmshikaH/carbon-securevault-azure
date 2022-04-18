/*
 * Copyright (c) 2022, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wso2.carbon.securevault.azure.commons;

import com.azure.core.credential.TokenCredential;
import com.azure.identity.AzureCliCredentialBuilder;
import com.azure.identity.DefaultAzureCredentialBuilder;
import com.azure.identity.EnvironmentCredentialBuilder;
import com.azure.identity.ManagedIdentityCredentialBuilder;
import com.azure.security.keyvault.secrets.SecretClient;
import com.azure.security.keyvault.secrets.SecretClientBuilder;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.securevault.azure.exception.AzureSecretRepositoryException;

import java.util.Properties;

import static org.wso2.carbon.securevault.azure.commons.Constants.AZURE;
import static org.wso2.carbon.securevault.azure.commons.Constants.DOT;
import static org.wso2.carbon.securevault.azure.commons.Constants.VAULT;

/**
 * Utils class to build the Secret Client used in secret retrieval by
 * reading the relevant configurations and using them accordingly.
 */
public class SecretClientUtils {

    private static final String CREDENTIAL = "credential";
    private static final String CREDENTIAL_CHAIN = "chain";
    private static final String CREDENTIAL_CLI = "cli";
    private static final String CREDENTIAL_ENV = "env";
    private static final String CREDENTIAL_MI = "mi";
    private static final String HTTPS_COLON_DOUBLE_SLASH = "https://";
    private static final String KEY_VAULT_NAME = "keyVaultName";
    private static final String MANAGED_IDENTITY_CLIENT_ID = "managedIdentityClientId";
    private static final String NET = "net";
    private static final Log log = LogFactory.getLog(SecretClientUtils.class);
    private static SecretClient secretClient;
    private static String credential;
    private static String keyVaultName;
    private static String managedIdentityClientId;

    /**
     * Builds the secret client to be used in secret retrieval using the Key Vault Url
     * and the user's preferred credential.
     *
     * @param properties Configuration properties from file.
     * @return the Secret Client to be used in secret retrieval.
     * @throws AzureSecretRepositoryException If the configurations are invalid.
     */
    public static SecretClient buildSecretClient(Properties properties) throws AzureSecretRepositoryException {

        if (log.isDebugEnabled()) {
            log.debug("Initializing Azure Key Vault connection.");
        }

        loadConfigurations(properties);

        secretClient = new SecretClientBuilder()
                .vaultUrl(HTTPS_COLON_DOUBLE_SLASH + keyVaultName + DOT + VAULT + DOT + AZURE + DOT + NET)
                .credential(createChosenCredential(credential))
                .buildClient();

        return secretClient;
    }

    /**
     * Reads the configuration properties required to build the Secret Client.
     *
     * @param properties Configuration properties from file.
     * @throws AzureSecretRepositoryException If the configurations are invalid.
     */
    public static void loadConfigurations(Properties properties) throws AzureSecretRepositoryException {

        if (log.isDebugEnabled()) {
            log.debug("Loading Carbon Secure Vault configurations for Azure Key Vault.");
        }

        ConfigUtils configUtils = ConfigUtils.getInstance();
        keyVaultName = configUtils.getConfig(properties, KEY_VAULT_NAME, null);

        if (StringUtils.isNotEmpty(keyVaultName)) {
            credential = configUtils.getConfig(properties, CREDENTIAL, null);
            if (StringUtils.isNotEmpty(credential)) {
                if (credential.equals(CREDENTIAL_MI) || credential.equals(CREDENTIAL_CHAIN)) {
                    managedIdentityClientId = configUtils.getConfig(properties, MANAGED_IDENTITY_CLIENT_ID, null);
                }
            } else {
                throw new AzureSecretRepositoryException("Authentication credential not configured. Configure as " +
                        "'env', 'mi', cli' or 'chain' to use Environment Credential Authentication, Managed Identity" +
                        " Authentication or Default Azure Credential Chain Authentication respectively.");
            }
        } else {
            throw new AzureSecretRepositoryException("Key Vault name not configured. Key Vault name cannot be null.");
        }
    }

    /**
     * Creates a credential to use in authentication based on the choice set by the user.
     *
     * @param credential Credential choice given by user.
     * @return Credential to be used in authentication.
     * @throws AzureSecretRepositoryException If the authentication credential choice is invalid.
     */
    private static TokenCredential createChosenCredential(String credential) throws AzureSecretRepositoryException {

        TokenCredential tokenCredential;

        switch(credential) {
            case CREDENTIAL_ENV:
                tokenCredential = new EnvironmentCredentialBuilder().
                        build();
                break;

            case CREDENTIAL_MI:
                tokenCredential = new ManagedIdentityCredentialBuilder()
                        .clientId(managedIdentityClientId)
                        .build();
                break;

            case CREDENTIAL_CLI:
                tokenCredential = new AzureCliCredentialBuilder()
                        .build();
                break;

            case CREDENTIAL_CHAIN:
                tokenCredential = new DefaultAzureCredentialBuilder()
                        .managedIdentityClientId(managedIdentityClientId)
                        .build();
                break;

            default:
                throw new AzureSecretRepositoryException("Invalid choice for Key Vault authentication credential." +
                        " Set value to one out of 'env', 'mi', 'cli' or 'chain' to use " +
                        "Environment Credential Authentication, Managed Identity Authentication or " +
                        "Default Azure Credential Chain Authentication respectively.");
        }

        return tokenCredential;
    }

    /**
     * Gets the Secret Client to be used in secret retrieval.
     *
     * @return The Secret Client.
     */
    public static SecretClient getSecretClient() {
        return secretClient;
    }
}
