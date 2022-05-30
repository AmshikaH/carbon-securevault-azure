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

import com.azure.core.exception.ResourceNotFoundException;
import com.azure.security.keyvault.secrets.SecretClient;
import com.azure.security.keyvault.secrets.models.KeyVaultSecret;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.securevault.azure.commons.ConfigUtils;
import org.wso2.carbon.securevault.azure.commons.SecretClientUtils;
import org.wso2.carbon.securevault.azure.exception.AzureSecretRepositoryException;
import org.wso2.securevault.CipherFactory;
import org.wso2.securevault.CipherOperationMode;
import org.wso2.securevault.DecryptionProvider;
import org.wso2.securevault.EncodingType;
import org.wso2.securevault.definition.CipherInformation;
import org.wso2.securevault.keystore.IdentityKeyStoreWrapper;
import org.wso2.securevault.keystore.KeyStoreWrapper;
import org.wso2.securevault.keystore.TrustKeyStoreWrapper;
import org.wso2.securevault.secret.SecretRepository;

import java.nio.charset.StandardCharsets;
import java.util.Properties;

import static org.wso2.carbon.securevault.azure.commons.Constants.AZURE_SECRET_CALLBACK_HANDLER;
import static org.wso2.carbon.securevault.azure.commons.Constants.DELIMITER;
import static org.wso2.carbon.securevault.azure.commons.Constants.DOT;
import static org.wso2.carbon.securevault.azure.commons.Constants.ENCRYPTION_ENABLED;
import static org.wso2.carbon.securevault.azure.commons.Constants.KEY;
import static org.wso2.carbon.securevault.azure.commons.Constants.REGEX;
import static org.wso2.carbon.securevault.azure.commons.Constants.STORE;

/**
 * Extension to facilitate the use of an Azure Key Vault as an external secret repository.
 */
public class AzureSecretRepository implements SecretRepository {

    private static final Log log = LogFactory.getLog(AzureSecretRepository.class);
    private static final String ALGORITHM = "algorithm";
    private static final String DEFAULT_ALGORITHM = "RSA";
    private static final String TRUSTED = "trusted";
    private Boolean encryptionEnabled = false;
    private SecretClient secretClient;
    private DecryptionProvider baseCipher;
    private ConfigUtils configUtils;
    private SecretRepository parentRepository;
    private IdentityKeyStoreWrapper identityKeyStoreWrapper;
    private TrustKeyStoreWrapper trustKeyStoreWrapper;

    /**
     * Creates an AzureSecretRepository by setting the identity keystore wrapper and trust keystore wrapper with
     * identityKeyStoreWrapper and trustKeyStoreWrapper, respectively.
     *
     * @param identityKeyStoreWrapper Identity keystore wrapper.
     * @param trustKeyStoreWrapper Trust keystore wrapper.
     */
    public AzureSecretRepository(IdentityKeyStoreWrapper identityKeyStoreWrapper,
                                 TrustKeyStoreWrapper trustKeyStoreWrapper) {

        this.identityKeyStoreWrapper = identityKeyStoreWrapper;
        this.trustKeyStoreWrapper = trustKeyStoreWrapper;
    }

    /**
     * Constructor with no parameters to be used with the novel configuration of Carbon Secure Vault.
     */
    public AzureSecretRepository() {
    }

    /**
     * Initializes the Key Vault as a Secret Repository.
     *
     * @param properties Configuration properties from file.
     * @param id Identifier to identify properties related to the corresponding repository.
     */
    @Override
    public void init(Properties properties, String id) {

        try {
            secretClient = SecretClientUtils.getSecretClient(properties);
            if (!AZURE_SECRET_CALLBACK_HANDLER.equals(id)) {
                configUtils = ConfigUtils.getInstance();
                encryptionEnabled = Boolean.parseBoolean(configUtils.getConfig(properties, ENCRYPTION_ENABLED, null));
                if (encryptionEnabled) {
                    initDecryptionProvider(properties);
                }
            }
        } catch (AzureSecretRepositoryException e) {
            log.error("Failed to build secret client.", e);
        }
    }

    /**
     * Retrieves a secret from the Key Vault and, if encryption has been enabled,
     * decrypts the retrieved value before returning it.
     *
     * @param alias The name and version (the latter is optional) of the secret being retrieved.
     * @return The secret corresponding to the alias from the Key Vault. If not found, returns an empty String.
     */
    @Override
    public String getSecret(String alias) {

        /* If no secret was retrieved, an empty String would be returned. If a runtime exception is thrown,
        secret retrieval is attempted repeatedly in a loop for certain secrets, which would prevent moving on to the
        next step or the server breaking.*/
        String secret = "";
        try {
            secret = retrieveSecretFromVault(alias);
        } catch (AzureSecretRepositoryException e) {
            log.error("Retrieval of secret with reference '" + alias.replaceAll(REGEX, "")
                    + "' from Azure Key Vault failed. Returning empty String.", e);
        }
        if (StringUtils.isNotEmpty(secret)) {
            if (encryptionEnabled) {
                secret = new String(baseCipher.decrypt(secret.trim().getBytes(StandardCharsets.UTF_8)),
                        StandardCharsets.UTF_8);
                if (log.isDebugEnabled()) {
                    log.debug("Retrieved secret was successfully decrypted.");
                }
            }
            if (log.isDebugEnabled()) {
                log.debug("Secret with reference '" + alias.replaceAll(REGEX, "")
                        + "' was successfully retrieved from Azure Key Vault.");
            }
        }
        return secret;
    }

    /**
     * Gets the encrypted value of the secret corresponding to the alias.
     *
     * @return encrypted value of secret stored in Key Vault if encryption has been enabled.
     */
    @Override
    public String getEncryptedData(String alias) {

        if (encryptionEnabled) {
            try {
                return retrieveSecretFromVault(alias);
            } catch (AzureSecretRepositoryException e) {
                log.error("Retrieval of encrypted data of secret with reference '" +
                        alias.replaceAll(REGEX, "") + "' from Azure Key Vault failed. Returning empty String.");
                return "";
            }
        } else {
            throw new UnsupportedOperationException("Encryption has not been enabled.");
        }
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
     * Initializes the DecryptionProvider to be used if encryption has been enabled.
     *
     * @param properties Configuration properties from file.
     */
    private void initDecryptionProvider(Properties properties) {

        String algorithm = configUtils.getConfig(properties, ALGORITHM, DEFAULT_ALGORITHM);
        String keyStore = properties.getProperty(DOT + KEY + StringUtils.capitalise(STORE));
        KeyStoreWrapper keyStoreWrapper;
        if (TRUSTED.equals(keyStore)) {
            keyStoreWrapper = trustKeyStoreWrapper;
        } else {
            keyStoreWrapper = identityKeyStoreWrapper;
        }

        CipherInformation cipherInformation = new CipherInformation();
        cipherInformation.setAlgorithm(algorithm);
        cipherInformation.setCipherOperationMode(CipherOperationMode.DECRYPT);
        cipherInformation.setInType(EncodingType.BASE64);
        baseCipher = CipherFactory.createCipher(cipherInformation, keyStoreWrapper);
    }

    /**
     * Retrieves a secret from the Key Vault according to the specified version.
     * If a secret version has not been specified, the latest version is retrieved.
     *
     * @param alias The name and version (the latter is optional) of the secret being retrieved.
     * @return the secret value retrieved from the Key Vault.
     */
    public String retrieveSecretFromVault(String alias) throws AzureSecretRepositoryException {

        String secret = "";
        if (secretClient != null) {
            try {
                String[] aliasComponents = parseSecretReference(alias);
                KeyVaultSecret retrievedSecret = secretClient.getSecret(aliasComponents[0], aliasComponents[1]);
                secret = retrievedSecret.getValue();
            } catch (ResourceNotFoundException e) {
                throw new AzureSecretRepositoryException("Secret not found in Key Vault.", e);
            }
        }
        return secret;
    }

    /**
     * Parses a secret reference into the secret's name and version.
     *
     * @param alias The secret reference comprising the name and version (the latter is optional)
     *              of the secret being retrieved.
     * @return An array comprising the name and version of the secret.
     * @throws AzureSecretRepositoryException If parsing of the secret reference failed.
     */
    private String[] parseSecretReference(String alias) throws AzureSecretRepositoryException {

        String[] aliasComponents = {alias, null};
        if (StringUtils.isNotEmpty(alias)) {
            if (alias.contains(DELIMITER)) {
                if (StringUtils.countMatches(alias, DELIMITER) == 1) {
                    aliasComponents = alias.split(DELIMITER, -1);
                    if (StringUtils.isEmpty(aliasComponents[0])) {
                        throw new AzureSecretRepositoryException("Secret name cannot be empty.");
                    }
                } else {
                    throw new AzureSecretRepositoryException("Syntax error in secret reference '" +
                            alias.replaceAll(REGEX, "") + "'. Secret reference should be in the format " +
                            "'secretName_secretVersion'. Note that there should be only one underscore.");
                }
            }
        } else {
            throw new AzureSecretRepositoryException("Secret alias cannot be empty.");
        }
        if (log.isDebugEnabled()) {
            if (StringUtils.isNotEmpty(aliasComponents[1])) {
                log.debug("Secret version '" + aliasComponents[1].replaceAll(REGEX, "") + "' found for secret"
                        + " '" + aliasComponents[0] + "'. Retrieving specified version of secret.");
            } else {
                log.debug("Secret version not found for secret '" + alias.replaceAll(REGEX, "") +
                        "'. Retrieving latest version of secret.");
            }
        }
        return aliasComponents;
    }
}
