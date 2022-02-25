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

package org.wso2.carbon.securevault.azure.repository;

import com.azure.core.credential.TokenCredential;
import com.azure.core.exception.ResourceNotFoundException;
import com.azure.identity.AzureCliCredentialBuilder;
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
import org.wso2.carbon.securevault.azure.exception.AzureKeyVaultException;
import org.wso2.securevault.secret.SecretRepository;

import java.util.Locale;
import java.util.Properties;

import static org.wso2.carbon.securevault.azure.common.AzureKeyVaultConstants.DOT;
import static org.wso2.carbon.securevault.azure.common.AzureKeyVaultConstants.IDENTITY;
import static org.wso2.carbon.securevault.azure.common.AzureKeyVaultConstants.KEY;
import static org.wso2.carbon.securevault.azure.common.AzureKeyVaultConstants.STORE;

/**
 * Extension to facilitate the use of an Azure Key Vault as an external secret repository.
 */
public class AzureKeyVaultRepository implements SecretRepository {

    private static final String AZURE = "azure";
    private static final String CHAIN_CREDENTIAL = "chain";
    private static final String CLI_CREDENTIAL = "cli";
    private static final String CREDENTIAL = "CREDENTIAL";
    private static final String DELIMITER = "_";
    private static final String ENV_CREDENTIAL = "env";
    private static final String MI_CLIENT_ID = "MI_CLIENT_ID";
    private static final String MI_CREDENTIAL = "mi";
    private static final String HTTPS_COLON_DOUBLE_SLASH = "https://";
    private static final String KV_NAME = "KV_NAME";
    private static final String KEY_VAULT_NAME = "keyVaultName";
    private static final String MANAGED_IDENTITY_CLIENT_ID = "managedIdentityClientId";
    private static final String NET = "net";
    private static final String PROPERTIES = "properties";
    private static final String REGEX = "[\r\n]";
    private static final String REPOSITORIES = "repositories";
    private static final String SECRET_CALLBACK_HANDLER =
            "org.wso2.carbon.securevault.azure.handler.AzureKeyVaultSecretCallbackHandler";
    private static final String SECRET_PROVIDER = "secretProvider";
    private static final String SECRET_PROVIDERS = "secretProviders";
    private static final String SECRET_REPOSITORIES = "secretRepositories";
    private static final String VAULT = "vault";
    private static final Log log = LogFactory.getLog(AzureKeyVaultRepository.class);
    private static String credential;
    private static String keyVaultName;
    private static String managedIdentityClientId;
    private static SecretClient secretClient;
    private SecretRepository parentRepository;

    /**
     * Initializes the Key Vault as a Secret Repository by providing configuration properties.
     *
     * @param properties Configuration properties from file.
     * @param id Identifier to identify properties related to the corresponding repository.
     */
    @Override
    public void init(Properties properties, String id) {

        if (log.isDebugEnabled()) {
            log.debug("Initializing Azure Key Vault connection.");
        }

        String keyStore = properties.getProperty(KEY + STORE + DOT + IDENTITY + DOT + STORE + DOT + SECRET_PROVIDER);
        String primaryKey = properties.getProperty(KEY + STORE + DOT + IDENTITY + DOT + KEY + DOT + SECRET_PROVIDER);

        if (!(keyStore.equals(SECRET_CALLBACK_HANDLER) && primaryKey.equals(SECRET_CALLBACK_HANDLER))) {
            try {
                buildSecretClient(properties);
            } catch (AzureKeyVaultException e) {
                log.error("Building secret client failed.", e);
            }
        }
    }

    /**
     * Retrieves a secret from the Key Vault according to the specified version.
     * If a secret version has not been specified, the latest version is retrieved.
     *
     * @param alias The name and version (the latter is optional) of the secret being retrieved.
     * @return The secret corresponding to the alias from the Key Vault. If not found, returns an empty String.
     */
    @Override
    public String getSecret(String alias) {

        String secret = "";

        if (StringUtils.isNotEmpty(keyVaultName)) {

            try {
                String[] aliasComponents = parseSecretReference(alias);
                KeyVaultSecret retrievedSecret = secretClient.getSecret(aliasComponents[0], aliasComponents[1]);
                secret = retrievedSecret.getValue();
            } catch (ResourceNotFoundException e) {
                log.error("Error occurred during secret retrieval. Check vault and/or secret configuration.", e);
            }
        }

        if (StringUtils.isNotEmpty(secret)) {
            log.debug("Secret was successfully retrieved.");
        } else {
            log.error("Secret retrieval failed. Value set to empty string.");
        }

        return secret;
    }

    /**
     * Gets the encrypted value of the secret corresponding to the alias.
     * This feature is not supported by this extension.
     *
     * @throws UnsupportedOperationException - always
     */
    @Override
    public String getEncryptedData(String alias) {
        throw new UnsupportedOperationException();
    }

    /**
     * Sets the parent repository. Allows secret repositories to be set in a chain
     * so that one repository can get secrets from another.
     */
    @Override
    public void setParent(SecretRepository parent) {
        this.parentRepository = parent;
    }

    /**
     * Gets the parent repository.
     *
     * @return Parent repository.
     */
    @Override
    public SecretRepository getParent() {
        return this.parentRepository;
    }

    /**
     * Parses a secret reference into the secret's name and version.
     *
     * @param alias The name and version (the latter is optional) of the secret being retrieved.
     * @return The secret corresponding to the alias in the Key Vault.
     */
    private String[] parseSecretReference(String alias) {

        String[] aliasComponents = {alias, null};

        if (alias.contains(DELIMITER)) {
            if (StringUtils.countMatches(alias, DELIMITER) == 1) {

                aliasComponents = alias.split(DELIMITER);

                if (log.isDebugEnabled()) {
                    if (StringUtils.isNotEmpty(aliasComponents[1])) {
                        log.debug("Secret version found. Retrieving the specified version of secret.");
                    } else {
                        log.debug("Secret version not found. Retrieving latest version of secret.");
                    }
                }
            } else {
                throw new IllegalArgumentException("Syntax error in secret reference. Secret reference " +
                        "should be in the format 'secretName_secretVersion'. " +
                        "Note that there should be only one underscore.");
            }
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Secret version not found. Retrieving latest version of secret.");
            }
        }

        return aliasComponents;
    }

    /**
     * Builds a secret client to be used in secret retrieval using the Key Vault Url
     * and the user's preferred credential.
     *
     * @param properties Configuration properties from file.
     */
    public static void buildSecretClient(Properties properties) throws AzureKeyVaultException {

        readConfigProperties(properties);
        secretClient = new SecretClientBuilder()
                .vaultUrl(HTTPS_COLON_DOUBLE_SLASH + keyVaultName + DOT + VAULT + DOT + AZURE + DOT + NET)
                .credential(createChosenCredential(credential))
                .buildClient();
    }

    /**
     * Reads Carbon Secure Vault configuration properties.
     *
     * @param properties Configuration properties from file.
     * @throws AzureKeyVaultException if the Key Vault name has not been provided.
     */
    private static void readConfigProperties(Properties properties) throws AzureKeyVaultException {

        String legacyProvidersString = properties.getProperty(SECRET_REPOSITORIES, null);
        String propertyPrefix;

        if (StringUtils.isEmpty(legacyProvidersString)) {
            if (log.isDebugEnabled()) {
                log.debug("Legacy provider not found. Using novel configurations.");
            }
            propertyPrefix = SECRET_PROVIDERS + DOT + VAULT + DOT + REPOSITORIES + DOT +
                    AZURE + DOT + PROPERTIES + DOT;
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Legacy provider found. Using legacy configurations.");
            }
            propertyPrefix = SECRET_REPOSITORIES + DOT + VAULT + DOT + PROPERTIES + DOT;
        }

        keyVaultName = properties.getProperty(propertyPrefix + KEY_VAULT_NAME);
        keyVaultName = getConfig(keyVaultName, KV_NAME, "Key Vault name");

        if (StringUtils.isNotEmpty(keyVaultName)) {
            credential = properties.getProperty(propertyPrefix + CREDENTIAL.toLowerCase(Locale.ROOT));
            credential = getConfig(credential, CREDENTIAL, "Credential choice");
            if (StringUtils.isNotEmpty(credential)) {
                if (credential.equals(MI_CREDENTIAL) || credential.equals(CHAIN_CREDENTIAL)) {
                    managedIdentityClientId = properties.getProperty(propertyPrefix + MANAGED_IDENTITY_CLIENT_ID);
                    managedIdentityClientId = getConfig(managedIdentityClientId, MI_CLIENT_ID,
                            "Managed identity client id");
                }
            }
        } else {
            throw new AzureKeyVaultException("Error in Key Vault configuration.");
        }
    }

    /**
     * Reads configuration properties from environment variables if not found in configuration file.
     *
     * @param value Value of the configuration property.
     * @param envProperty Name of the environment variable that stores the value of the configuration property.
     * @param propertyName Name of the property being read.
     */
    private static String getConfig(String value, String envProperty, String propertyName) {

        propertyName = propertyName.replaceAll(REGEX, "");
        if (StringUtils.isEmpty(value)) {

            if (log.isDebugEnabled()) {
                log.debug(propertyName + " not found in configuration file. Checking environment variables.");
            }

            value = System.getenv(envProperty);

            if (StringUtils.isEmpty(value)) {
                log.error(propertyName + " not found as an environment variables. Value cannot be null " +
                        "and must be provided in configuration file or as an environment variable.");
            } else {
                if (log.isDebugEnabled()) {
                    log.debug(propertyName + " found as an environment variable. Value set to this.");
                }
            }
        } else {
            if (log.isDebugEnabled()) {
                log.debug(propertyName + " found in configuration file. Value set to this.");
            }
        }

        return value;
    }

    /**
     * Creates a credential to use in authentication based on choice set by user.
     *
     * @param credential Credential choice given by user.
     * @return Credential to be used in authentication.
     * @throws CredentialUnavailableException if the authentication credential choice
     *                                        has not been provided or is invalid.
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

                case CLI_CREDENTIAL:
                    tokenCredential = new AzureCliCredentialBuilder()
                            .build();
                    break;

                case CHAIN_CREDENTIAL:
                    tokenCredential = new DefaultAzureCredentialBuilder()
                            .managedIdentityClientId(managedIdentityClientId)
                            .build();
                    break;

                default:
                    throw new CredentialUnavailableException("Invalid choice for Key Vault authentication credential." +
                            " Set value to one out of 'env', 'mi', 'cli' or 'chain' to use " +
                            "Environment Credential Authentication, Managed Identity Authentication or " +
                            "Default Azure Credential Chain Authentication respectively.");
            }
        } else {
            throw new CredentialUnavailableException("Key Vault authentication credential not configured. " +
                    "Set configuration property or environment variable with 'env', 'mi', cli' or 'chain' to use " +
                    "Environment Credential Authentication, Managed Identity Authentication or " +
                    "'Default Azure Credential Chain Authentication respectively.");
        }

        return tokenCredential;
    }
}
