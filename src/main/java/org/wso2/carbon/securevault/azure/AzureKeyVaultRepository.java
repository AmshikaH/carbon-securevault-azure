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

package org.wso2.carbon.securevault.azure;

import com.azure.identity.AzureCliCredential;
import com.azure.identity.AzureCliCredentialBuilder;
import com.azure.identity.ChainedTokenCredential;
import com.azure.identity.ChainedTokenCredentialBuilder;
import com.azure.identity.EnvironmentCredential;
import com.azure.identity.EnvironmentCredentialBuilder;
import com.azure.identity.ManagedIdentityCredential;
import com.azure.identity.ManagedIdentityCredentialBuilder;
import com.azure.security.keyvault.secrets.SecretClient;
import com.azure.security.keyvault.secrets.SecretClientBuilder;
import com.azure.security.keyvault.secrets.models.KeyVaultSecret;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.securevault.secret.SecretRepository;
import java.util.Properties;

import static org.wso2.carbon.securevault.azure.AzureKeyVaultConstants.AZURE;
import static org.wso2.carbon.securevault.azure.AzureKeyVaultConstants.DOT;
import static org.wso2.carbon.securevault.azure.AzureKeyVaultConstants.ENV_MI_CLIENT_ID;
import static org.wso2.carbon.securevault.azure.AzureKeyVaultConstants.HTTPS_COLON_DOUBLE_SLASH;
import static org.wso2.carbon.securevault.azure.AzureKeyVaultConstants.IDENTITY;
import static org.wso2.carbon.securevault.azure.AzureKeyVaultConstants.KEY;
import static org.wso2.carbon.securevault.azure.AzureKeyVaultConstants.KEY_VAULT_NAME;
import static org.wso2.carbon.securevault.azure.AzureKeyVaultConstants.MANAGED_IDENTITY_CLIENT_ID;
import static org.wso2.carbon.securevault.azure.AzureKeyVaultConstants.NET;
import static org.wso2.carbon.securevault.azure.AzureKeyVaultConstants.PROPERTIES;
import static org.wso2.carbon.securevault.azure.AzureKeyVaultConstants.REPOSITORIES;
import static org.wso2.carbon.securevault.azure.AzureKeyVaultConstants.SECRET_CALLBACK_HANDLER;
import static org.wso2.carbon.securevault.azure.AzureKeyVaultConstants.SECRET_PROVIDER;
import static org.wso2.carbon.securevault.azure.AzureKeyVaultConstants.SECRET_PROVIDERS;
import static org.wso2.carbon.securevault.azure.AzureKeyVaultConstants.SECRET_REPOSITORIES;
import static org.wso2.carbon.securevault.azure.AzureKeyVaultConstants.STORE;
import static org.wso2.carbon.securevault.azure.AzureKeyVaultConstants.VAULT;

/**
 * Extension to facilitate the use of an Azure Key Vault as an external secret repository.
 */
public class AzureKeyVaultRepository implements SecretRepository {

    private static final Log log = LogFactory.getLog(AzureKeyVaultRepository.class);
    private static String keyVaultName;
    private static String managedIdentityClientId;
    private static SecretClient secretClient;

    /**
     * Initializes the Azure Key Vault as a Secret Repository by providing configuration properties.
     *
     * @param properties Configuration properties.
     * @param id Identifier to identify properties related to the corresponding repository.
     */
    @Override
    public void init(Properties properties, String id) {

        String keyStore = properties.getProperty(KEY + STORE + DOT + IDENTITY + DOT + STORE + DOT + SECRET_PROVIDER);
        String primaryKey = properties.getProperty(KEY + STORE + DOT + IDENTITY + DOT + KEY + DOT + SECRET_PROVIDER);

        if (!(keyStore.equals(SECRET_CALLBACK_HANDLER) && primaryKey.equals(SECRET_CALLBACK_HANDLER))) {
            authenticateToKeyVault(properties);
        }
    }

    /**
     * Retrieves the secret from the Azure Key Vault.
     *
     * @param alias The name and version (the latter is optional) of the secret being retrieved.
     * @return The secret corresponding to the alias from the Azure Key Vault. If not found, returns an empty String.
     */
    @Override
    public String getSecret(String alias) {

        String secret = "";

        if (!StringUtils.isEmpty(keyVaultName)) {
            try {
                secret = retrieveSecretFromVault(alias);
            } catch (Exception e) {
                log.error("Error occurred during secret retrieval. Check vault and/or secret configuration.", e);
            }
        }

        if (StringUtils.isEmpty(secret)) {
            log.error("Secret retrieval failed. Value set to empty string.");
        }

        return secret;
    }

    @Override
    public String getEncryptedData(String alias) {
        // This method was implemented from the interface and has been intentionally left empty.
        return null;
    }

    @Override
    public void setParent(SecretRepository parent) {
        // This method was implemented from the interface and has been intentionally left empty.
    }

    @Override
    public SecretRepository getParent() {
        // This method was implemented from the interface and has been intentionally left empty.
        return null;
    }

    /**
     * Retrieves the secret according to the specified version.
     * If a secret version has not been specified, the latest version is retrieved.
     *
     * @param alias The name and version (the latter is optional) of the secret being retrieved.
     * @return The secret corresponding to the alias from the Azure Key Vault.
     */
    private String retrieveSecretFromVault(String alias) {

        String secretName = alias;
        String secretVersion = "";

        if (alias.contains("_")) {
            int underscoreIndex = alias.indexOf("_");

            secretName = alias.substring(0, underscoreIndex);
            secretVersion = alias.substring(underscoreIndex + 1);

            if (log.isDebugEnabled()) {
                log.debug("Secret version found. Retrieving the specified version of secret.");
            }
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Secret version not found. Retrieving latest version of secret.");
            }
        }

        KeyVaultSecret retrievedSecret = secretClient.getSecret(secretName, secretVersion);
        String secret = retrievedSecret.getValue();

        return secret;
    }

    /**
     * Reads Carbon Secure Vault configuration properties.
     *
     * @param properties Configuration properties.
     */
    public static void readConfigProperties(Properties properties) {

        String legacyProvidersString = properties.getProperty("secretRepositories", null);
        boolean novelFlag;

        if (StringUtils.isEmpty(legacyProvidersString)) {
            if (log.isDebugEnabled()) {
                log.debug("Legacy provider not found. Using novel configurations.");
            }
            novelFlag = true;
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Legacy provider found. Using legacy configurations.");
            }
            novelFlag = false;
        }

        String legacyPropertyPrefix = SECRET_REPOSITORIES + DOT + VAULT + DOT + PROPERTIES + DOT;
        String novelPropertyPrefix = SECRET_PROVIDERS + DOT + VAULT + DOT + REPOSITORIES + DOT +
                AZURE + PROPERTIES + DOT;

        String propertyKeyVaultName = novelFlag ? (novelPropertyPrefix + KEY_VAULT_NAME) :
                (legacyPropertyPrefix + KEY_VAULT_NAME);
        String propertyManagedIdentityClientID = novelFlag ? (novelPropertyPrefix + MANAGED_IDENTITY_CLIENT_ID) :
                (legacyPropertyPrefix + MANAGED_IDENTITY_CLIENT_ID);

        keyVaultName = properties.getProperty(propertyKeyVaultName);
        managedIdentityClientId = properties.getProperty(propertyManagedIdentityClientID);
    }

    /**
     * Creates a credential chain which attempts to authenticate to the Azure Key Vault via environment credentials,
     * a managed identity or the Azure CLI in order. If none are available, authentication fails.
     *
     * @return The credential chain mentioned above.
     */
    private static ChainedTokenCredential createAuthenticationChain() {

        EnvironmentCredential environmentCredential = new EnvironmentCredentialBuilder()
                .build();

        ManagedIdentityCredential managedIdentityCredential = new ManagedIdentityCredentialBuilder()
                .clientId(managedIdentityClientId)
                .build();

        AzureCliCredential azureCliCredential = new AzureCliCredentialBuilder().
                build();

        ChainedTokenCredential credentialChain = new ChainedTokenCredentialBuilder()
                .addFirst(environmentCredential)
                .addLast(managedIdentityCredential)
                .addLast(azureCliCredential)
                .build();

        return  credentialChain;
    }

    /**
     * Authenticates to the Key Vault using a credential chain.
     */
    public static void authenticateToKeyVault(Properties properties) {

        if (log.isDebugEnabled()) {
            log.debug("Initializing Azure Key Vault connection.");
        }

        readConfigProperties(properties);

        if (StringUtils.isEmpty(keyVaultName)) {
            if (log.isDebugEnabled()) {
                log.error("Azure key vault name not found. Value cannot be null. " +
                        "Check whether the name of the vault has been configured properly.");
            }
        }

        if (StringUtils.isEmpty(managedIdentityClientId)) {
            if (log.isDebugEnabled()) {
                log.debug("Managed identity clientId not found in configuration file. Checking environment variables.");
            }

            managedIdentityClientId = System.getenv(ENV_MI_CLIENT_ID);

            if (StringUtils.isEmpty(managedIdentityClientId) && log.isDebugEnabled()) {
                log.debug("Managed identity clientId not found in environment variables. Value set to null.");
            }
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Managed identity clientId found in configuration file. Using configured value.");
            }
        }

        String keyVaultUri = HTTPS_COLON_DOUBLE_SLASH + keyVaultName + DOT + VAULT + DOT + AZURE + DOT + NET;
        secretClient = new SecretClientBuilder()
                .vaultUrl(keyVaultUri)
                .credential(createAuthenticationChain())
                .buildClient();
    }
}
