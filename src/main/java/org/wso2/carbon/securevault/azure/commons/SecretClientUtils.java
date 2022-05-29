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
import com.azure.identity.ClientSecretCredentialBuilder;
import com.azure.identity.DefaultAzureCredentialBuilder;
import com.azure.identity.EnvironmentCredentialBuilder;
import com.azure.identity.ManagedIdentityCredentialBuilder;
import com.azure.security.keyvault.secrets.SecretClient;
import com.azure.security.keyvault.secrets.SecretClientBuilder;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.securevault.azure.exception.AzureSecretRepositoryException;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.Properties;

import static org.wso2.carbon.securevault.azure.commons.Constants.AZURE;
import static org.wso2.carbon.securevault.azure.commons.Constants.DOT;
import static org.wso2.carbon.securevault.azure.commons.Constants.REGEX;
import static org.wso2.carbon.securevault.azure.commons.Constants.VAULT;

/**
 * Utils class to build the Secret Client used in secret retrieval by
 * reading the relevant configurations and using them accordingly.
 */
public class SecretClientUtils {

    private static final String CLIENT_ID_FILE_PATH = "clientIdFilePath";
    private static final String CLIENT_SECRET_FILE_PATH = "clientSecretFilePath";
    private static final String TENANT_ID_FILE_PATH = "tenantIdFilePath";
    private static final String CREDENTIAL = "credential";
    private static final String CREDENTIAL_CHAIN = "chain";
    private static final String CREDENTIAL_CLI = "cli";
    private static final String CREDENTIAL_ENV = "env";
    private static final String CREDENTIAL_FILE = "file";
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
    private static Properties properties;

    /**
     * Gets the secret client to be used in secret retrieval.
     *
     * @return The secret client to retrieve secrets from the configured Azure Key Vault.
     * @throws AzureSecretRepositoryException If an error occurs while building the secret client.
     */
    public static synchronized SecretClient getSecretClient(Properties properties)
            throws AzureSecretRepositoryException {

        if (secretClient == null) {
            secretClient = SecretClientUtils.buildSecretClient(properties);
        }
        return secretClient;
    }

    /**
     * Builds the secret client to be used in secret retrieval using the Key Vault Url
     * and the user's preferred credential.
     *
     * @param configProperties Configuration properties from file.
     * @return the Secret Client to be used in secret retrieval.
     * @throws AzureSecretRepositoryException If an error occurs while building the secret client.
     */
    public static SecretClient buildSecretClient(Properties configProperties) throws AzureSecretRepositoryException {

        if (log.isDebugEnabled()) {
            log.debug("Building secret client.");
        }
        properties = configProperties;
        loadConfigurations();
        secretClient = new SecretClientBuilder()
                .vaultUrl(HTTPS_COLON_DOUBLE_SLASH + keyVaultName + DOT + VAULT + DOT + AZURE + DOT + NET)
                .credential(createChosenCredential())
                .buildClient();
        return secretClient;
    }

    /**
     * Reads the configuration properties required to build the Secret Client.
     *
     * @throws AzureSecretRepositoryException If the configurations have not been provided.
     */
    public static void loadConfigurations() throws AzureSecretRepositoryException {

        if (log.isDebugEnabled()) {
            log.debug("Loading configurations for Azure Key Vault.");
        }
        ConfigUtils configUtils = ConfigUtils.getInstance();
        keyVaultName = configUtils.getConfig(properties, KEY_VAULT_NAME, null);
        if (StringUtils.isEmpty(keyVaultName)) {
            throw new AzureSecretRepositoryException("Key Vault name not provided.");
        }
        credential = configUtils.getConfig(properties, CREDENTIAL, null);
        if (StringUtils.isEmpty(credential)) {
            throw new AzureSecretRepositoryException("Authentication credential choice not provided.");
        }
        if (credential.equals(CREDENTIAL_MI) || credential.equals(CREDENTIAL_CHAIN)) {
            managedIdentityClientId = configUtils.getConfig(properties, MANAGED_IDENTITY_CLIENT_ID, null);
        }
    }

    /**
     * Creates a credential to use in authentication based on the choice set by the user.
     *
     * @return Credential to be used in authentication.
     * @throws AzureSecretRepositoryException If the authentication credential choice is invalid.
     */
    private static TokenCredential createChosenCredential() throws AzureSecretRepositoryException {

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
            case CREDENTIAL_FILE:
                tokenCredential = createClientSecretCredential();
                break;
            default:
                throw new AzureSecretRepositoryException("Invalid choice for Key Vault authentication credential.");
        }
        return tokenCredential;
    }

    /**
     * Creates a client secret credential to be used to authenticate to the Key Vault
     * by reading the authentication credential values from files if the authentication
     * credential choice has been set to "file".
     *
     * @return Client Secret Credential to be used in Key Vault authentication.
     * @throws AzureSecretRepositoryException If there was an error in reading the authentication credential values
     *                               from the files.
     */
    private static TokenCredential createClientSecretCredential() throws AzureSecretRepositoryException {

        if (log.isDebugEnabled()) {
            log.debug("Authenticating to Azure Key Vault via file credentials.");
        }
        return new ClientSecretCredentialBuilder()
                .clientId(readCredential(CLIENT_ID_FILE_PATH))
                .clientSecret(readCredential(CLIENT_SECRET_FILE_PATH))
                .tenantId(readCredential(TENANT_ID_FILE_PATH))
                .build();
    }

    /**
     * Reads authentication credential values from a file.
     *
     * @param credentialFileProperty Property to specify the path of the file containing the credential value.
     *                               This property may be set in the secret-conf.properties file or as an
     *                               environment variable.
     * @return The credential value read from the file.
     * @throws AzureSecretRepositoryException If there was an error in reading the authentication credential values
     *                               from the files.
     */
    @SuppressFBWarnings({"PATH_TRAVERSAL_IN"})
    private static String readCredential(String credentialFileProperty) throws AzureSecretRepositoryException {

        ConfigUtils configUtils = ConfigUtils.getInstance();
        String credentialFilePath = configUtils.getConfig(properties, credentialFileProperty, null);
        if (StringUtils.isEmpty(credentialFilePath)) {
            throw new AzureSecretRepositoryException(credentialFileProperty.replaceAll(REGEX, "") + " not provided.");
        }
        try (BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(new FileInputStream
                (credentialFilePath), StandardCharsets.UTF_8))) {
            String credentialValue = bufferedReader.readLine();
            if (StringUtils.isEmpty(credentialValue)) {
                throw new AzureSecretRepositoryException(credentialFileProperty.replaceAll(REGEX, "")
                        + " not found in file.");
            }
            return credentialValue;
        } catch (IOException e) {
            throw new AzureSecretRepositoryException("Error while loading " +
                    credentialFileProperty.replaceAll(REGEX, "") + " from file.", e);
        }
    }
}
