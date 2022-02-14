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

import com.azure.core.credential.TokenCredential;
import com.azure.identity.CredentialUnavailableException;
import com.azure.identity.DefaultAzureCredentialBuilder;
import com.azure.identity.EnvironmentCredentialBuilder;
import com.azure.identity.ManagedIdentityCredentialBuilder;
import com.azure.security.keyvault.secrets.SecretClient;
import com.azure.security.keyvault.secrets.SecretClientBuilder;
import com.azure.security.keyvault.secrets.models.KeyVaultSecret;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.securevault.secret.SecretRepository;

import java.lang.reflect.Array;
import java.net.UnknownHostException;
import java.util.Properties;

import static org.wso2.carbon.securevault.azure.AzureKeyVaultConstants.DOT;
import static org.wso2.carbon.securevault.azure.AzureKeyVaultConstants.IDENTITY;
import static org.wso2.carbon.securevault.azure.AzureKeyVaultConstants.KEY;
import static org.wso2.carbon.securevault.azure.AzureKeyVaultConstants.STORE;

/**
 * Extension to facilitate the use of an Azure Key Vault as an external secret repository.
 */
public class AzureKeyVaultRepository implements SecretRepository {

    private static final String AZURE = "azure";
    private static final String CHAIN_CREDENTIAL = "chain";
    private static final String CREDENTIAL = "CREDENTIAL";
    private static final String ENV_CREDENTIAL = "env";
    private static final String MI_CLIENT_ID = "MI_CLIENT_ID";
    private static final String MI_CREDENTIAL = "mi";
    private static final String HTTPS_COLON_DOUBLE_SLASH = "https://";
    private static final String KV_NAME = "KV_NAME";
    private static final String KEY_VAULT_NAME = "keyVaultName";
    private static final String MANAGED_IDENTITY_CLIENT_ID = "managedIdentityClientId";
    private static final String NET = "net";
    private static final String PROPERTIES = "properties";
    private static final String REPOSITORIES = "repositories";
    private static final String SECRET_CALLBACK_HANDLER =
            "org.wso2.carbon.securevault.azure.AzureKeyVaultSecretCallbackHandler";
    private static final String SECRET_PROVIDER = "secretProvider";
    private static final String SECRET_PROVIDERS = "secretProviders";
    private static final String SECRET_REPOSITORIES = "secretRepositories";
    private static final String VAULT = "vault";
    private static final Log log = LogFactory.getLog(AzureKeyVaultRepository.class);
    private static String credential;
    private static String keyVaultName;
    private static String managedIdentityClientId;
    private static SecretClient secretClient;

    /**
     * Initializes the Azure Key Vault as a Secret Repository by providing configuration properties.
     *
     * @param properties Configuration properties from file.
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

        if (StringUtils.isNotEmpty(keyVaultName)) {
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
     * @return The secret corresponding to the alias in the Key Vault.
     */
    private String retrieveSecretFromVault(String alias) {

        String secretName = alias;
        String secretVersion = "";

        if (alias.contains("_")) {
            int underscoreIndex = alias.indexOf("_");

            secretName = alias.substring(0, underscoreIndex);
            secretVersion = alias.substring(underscoreIndex + 1);

            if (log.isDebugEnabled()) {
                if (StringUtils.isNotEmpty(secretVersion)) {
                    log.debug("Secret version found. Retrieving the specified version of secret.");
                } else {
                    log.debug("Secret version not found. Retrieving latest version of secret.");
                }
            }
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Secret version not found. Retrieving latest version of secret.");
            }
        }

        KeyVaultSecret retrievedSecret = secretClient.getSecret(secretName, secretVersion);

        return retrievedSecret.getValue();
    }

    /**
     * Authenticates to the Key Vault using a credential chain.
     *
     * @param properties Configuration properties from file.
     */
    public static void authenticateToKeyVault(Properties properties) {

        if (log.isDebugEnabled()) {
            log.debug("Initializing Azure Key Vault connection.");
        }

        try {
            readConfigProperties(properties);
        } catch (UnknownHostException e) {
            log.error("Error in Key Vault configuration.", e);
        }

        try {
            secretClient = new SecretClientBuilder()
                    .vaultUrl(HTTPS_COLON_DOUBLE_SLASH + keyVaultName + DOT + VAULT + DOT + AZURE + DOT + NET)
                    .credential(createChosenCredential(credential))
                    .buildClient();
        } catch (CredentialUnavailableException e) {
            log.error("Building secret client failed.", e);
        }

    }

    /**
     * Reads Carbon Secure Vault configuration properties.
     *
     * @param properties Configuration properties from file.
     */
    private static void readConfigProperties(Properties properties) throws UnknownHostException {

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

        String propertyCredential = novelFlag ? (novelPropertyPrefix + CREDENTIAL.toLowerCase()) :
                (legacyPropertyPrefix + CREDENTIAL.toLowerCase());
        String propertyKeyVaultName = novelFlag ? (novelPropertyPrefix + KEY_VAULT_NAME) :
                (legacyPropertyPrefix + KEY_VAULT_NAME);
        String propertyManagedIdentityClientID = novelFlag ? (novelPropertyPrefix + MANAGED_IDENTITY_CLIENT_ID) :
                (legacyPropertyPrefix + MANAGED_IDENTITY_CLIENT_ID);

        keyVaultName = properties.getProperty(propertyKeyVaultName);
        managedIdentityClientId = properties.getProperty(propertyManagedIdentityClientID);
        credential = properties.getProperty(propertyCredential);

        readEnvProperties();

        if (StringUtils.isEmpty(keyVaultName)) {
            throw new UnknownHostException("Key Vault name not provided.");
        }
    }

    /**
     * Reads Carbon Secure Vault configuration properties from environment variables.
     */
    private static void readEnvProperties() {

        String [] credentialLogs = new String[4];
        credentialLogs [0] = "Credential choice not found in configuration file. Checking environment variables.";
        credentialLogs [1] = "Credential choice not found as an environment variables. Value cannot be null." +
                "Configure credential choice in configuration file or as an environment variable.";
        credentialLogs [2] = "Credential choice found as an environment variable. Value set to this.";
        credentialLogs [3] = "Credential choice found in configuration file. Value set to this.";
        credential = config(credential, CREDENTIAL, credentialLogs);

        String [] keyVaultNameLogs = new String[4];
        keyVaultNameLogs [0] = "Key Vault name not found in configuration file. Checking environment variables.";
        keyVaultNameLogs [1] = "Key Vault name not found not found as an environment variable. Value cannot be null. " +
                "Configure key vault name in configuration file or as an environment variable.";
        keyVaultNameLogs [2] = "Key Vault name found as an environment variable. Value set to this.";
        keyVaultNameLogs [3] = "Key Vault name found in configuration file. Value set to this.";
        keyVaultName = config(keyVaultName, KV_NAME, keyVaultNameLogs);

        if (StringUtils.isNotEmpty(credential)) {
            if (credential.equals(MI_CREDENTIAL) || credential.equals(CHAIN_CREDENTIAL)) {
                String [] managedIdentityClientIdLogs = new String[4];
                managedIdentityClientIdLogs [0] = "Managed identity clientId not found in configuration file. " +
                        "Checking environment variables.";
                managedIdentityClientIdLogs [1] = "Managed identity clientId not found in environment variables. " +
                        "Value set to null.";
                managedIdentityClientIdLogs [2] = "Managed identity client id found as an environment variable. " +
                        "Value set to this.";
                managedIdentityClientIdLogs [3] = "Managed identity clientId found in configuration file. " +
                        "Value set to this.";
                managedIdentityClientId = config(managedIdentityClientId, MI_CLIENT_ID, managedIdentityClientIdLogs);
            }
        }
    }

    /**
     * Reads configuration properties from environment variables if not found in configuration file.
     *
     * @param value Value of the configuration property
     * @param envProperty Name of the environment variable that stores the value of the configuration property
     * @param logs Set of logs used when reading configuration properties
     */
    private static String config(String value, String envProperty, String[] logs) {

        if (StringUtils.isEmpty(value)) {

            if (log.isDebugEnabled()) {
                log.debug(Array.get(logs, 0));
            }

            value = System.getenv(envProperty);

            if (StringUtils.isEmpty(value)) {
                log.error(Array.get(logs, 1));
            } else {

                if (log.isDebugEnabled()) {
                    log.debug(Array.get(logs, 2));
                }
            }
        } else {

            if (log.isDebugEnabled()) {
                log.debug(Array.get(logs, 3));
            }
        }

        return value;
    }

    /**
     * Creates a credential to use in authentication based on choice set by user.
     *
     * @param credential Credential choice given by user
     * @return Credential to be used in authentication
     */
    private static TokenCredential createChosenCredential(String credential) {

        TokenCredential tokenCredential;

        if (StringUtils.isNotEmpty(credential)) {
            switch(credential) {
                case ENV_CREDENTIAL:

                    tokenCredential = new EnvironmentCredentialBuilder().
                            build();
                    break;
                case MI_CREDENTIAL:

                    tokenCredential = new ManagedIdentityCredentialBuilder()
                            .clientId(managedIdentityClientId)
                            .build();
                    break;
                case CHAIN_CREDENTIAL:

                    tokenCredential = new DefaultAzureCredentialBuilder()
                            .managedIdentityClientId(managedIdentityClientId)
                            .build();
                    break;
                default:

                    throw new CredentialUnavailableException("Invalid choice for Key Vault authentication credential." +
                            " Set value to one out of 'env', 'mi' or 'chain' to use " +
                            "Environment Credential Authentication, Managed Identity Authentication or " +
                            "Default Azure Credential Chain Authentication respectively.");
            }
        } else {

            throw new CredentialUnavailableException("Key Vault authentication credential not configured. " +
                    "Set configuration property or environment variable with 'env', 'mi' or 'chain' to use " +
                    "Environment Credential Authentication, Managed Identity Authentication or " +
                    "'Default Azure Credential Chain Authentication respectively.");
        }

        return tokenCredential;
    }
}
