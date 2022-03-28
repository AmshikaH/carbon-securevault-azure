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

import static org.wso2.carbon.securevault.azure.commons.Constants.DELIMITER;
import static org.wso2.carbon.securevault.azure.commons.Constants.DOT;
import static org.wso2.carbon.securevault.azure.commons.Constants.ENCRYPTION_ENABLED;
import static org.wso2.carbon.securevault.azure.commons.Constants.HANDLER;
import static org.wso2.carbon.securevault.azure.commons.Constants.KEY;
import static org.wso2.carbon.securevault.azure.commons.Constants.REGEX;
import static org.wso2.carbon.securevault.azure.commons.Constants.STORE;

/**
 * Extension to facilitate the use of an Azure Key Vault as an external secret repository.
 */
public class AzureSecretRepository implements SecretRepository {

    private static final String ALGORITHM = "algorithm";
    private static final String DEFAULT_ALGORITHM = "RSA";
    private static final String TRUSTED = "trusted";
    private static final Log log = LogFactory.getLog(AzureSecretRepository.class);
    private Boolean encryptionEnabled;
    private SecretClient secretClient;
    private String algorithm;
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
     * Initializes the Key Vault as a Secret Repository.
     *
     * @param properties Configuration properties from file.
     * @param id Identifier to identify properties related to the corresponding repository.
     */
    @Override
    public void init(Properties properties, String id) {

        secretClient = SecretClientUtils.getSecretClient();
        if (secretClient == null) {
            try {
                secretClient = SecretClientUtils.buildSecretClient(properties);
            } catch (AzureSecretRepositoryException e) {
                throw new NullPointerException("Building secret client failed.");
            }
        }

        if (!id.equals(HANDLER)) {
            configUtils = ConfigUtils.getInstance();
            encryptionEnabled = Boolean.parseBoolean(configUtils.getConfig(properties, ENCRYPTION_ENABLED, null));
        }

        if (encryptionEnabled) {
            initDecryptionProvider(properties);
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

        String secret = retrieveSecretFromVault(alias);
        if (encryptionEnabled) {
            secret = new String(baseCipher.decrypt(secret.trim().getBytes(StandardCharsets.UTF_8)),
                    StandardCharsets.UTF_8);
            if (log.isDebugEnabled()) {
                log.debug("Retrieved secret was successfully decrypted.");
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
            return retrieveSecretFromVault(alias);
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

        algorithm = configUtils.getConfig(properties, ALGORITHM, DEFAULT_ALGORITHM);

        // Loads keystore
        String keyStore = properties.getProperty(DOT + KEY + StringUtils.capitalise(STORE));
        KeyStoreWrapper keyStoreWrapper;
        if (TRUSTED.equals(keyStore)) {
            keyStoreWrapper = trustKeyStoreWrapper;
        } else {
            keyStoreWrapper = identityKeyStoreWrapper;
        }

        // Creates a CipherInformation
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
    public String retrieveSecretFromVault(String alias) {

        String secret = "";

        try {
            String[]aliasComponents = parseSecretReference(alias);
            KeyVaultSecret retrievedSecret = this.secretClient.getSecret(aliasComponents[0], aliasComponents[1]);
            secret = retrievedSecret.getValue();
        } catch (AzureSecretRepositoryException e) {
            log.error("Error occurred during secret retrieval. Check vault and/or secret configuration: ", e);
        }

        if (StringUtils.isNotEmpty(secret)) {
            if (log.isDebugEnabled()) {
                log.debug("Secret with reference '" + alias.replaceAll(REGEX, "")
                        + "' was successfully retrieved from Azure Key Vault.");
            }
        } else {
            log.error("Retrieval of secret with reference '" + alias.replaceAll(REGEX, "")
                    + "' from Azure Key Vault failed. Value set to empty string.");
        }

        return secret;
    }

    /**
     * Parses a secret reference into the secret's name and version.
     *
     * @param alias The name and version (the latter is optional) of the secret being retrieved.
     * @return An array comprising the name and version of the secret.
     */
    private String[] parseSecretReference(String alias) throws AzureSecretRepositoryException {

        String[] aliasComponents = {alias, null};

        if (StringUtils.isNotEmpty(aliasComponents[0])) {
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
            throw new AzureSecretRepositoryException("Secret name cannot be empty.");
        }

        if (log.isDebugEnabled()) {
            if (StringUtils.isNotEmpty(aliasComponents[1])) {
                log.debug("Secret version '" + aliasComponents[1].replaceAll(REGEX, "") + "' found for secret"
                        + " '" + aliasComponents[0] + "'. Retrieving the specified version of secret.");
            } else {
                log.debug("Secret version not found for secret '" + alias.replaceAll(REGEX, "") +
                        "'. Retrieving latest version of secret.");
            }
        }

        return aliasComponents;
    }
}
