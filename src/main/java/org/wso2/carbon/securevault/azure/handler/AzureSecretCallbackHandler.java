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

package org.wso2.carbon.securevault.azure.handler;

import com.azure.core.exception.ResourceNotFoundException;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.securevault.azure.commons.ConfigUtils;
import org.wso2.carbon.securevault.azure.exception.AzureSecretRepositoryException;
import org.wso2.carbon.securevault.azure.repository.AzureSecretRepository;
import org.wso2.securevault.secret.AbstractSecretCallbackHandler;
import org.wso2.securevault.secret.SingleSecretCallback;

import java.io.Console;
import java.util.Properties;

import static org.wso2.carbon.securevault.azure.commons.Constants.DOT;
import static org.wso2.carbon.securevault.azure.commons.Constants.HANDLER;
import static org.wso2.carbon.securevault.azure.commons.Constants.KEY;
import static org.wso2.carbon.securevault.azure.commons.Constants.STORE;

/**
 * Secret Callback handler class used if the keystore and primary key passwords are stored in the
 * Azure Key Vault that stores the deployment secrets.
 */
public class AzureSecretCallbackHandler extends AbstractSecretCallbackHandler {

    private static final String ALIAS = "alias";
    private static final String IDENTITY = "identity";
    private static final String PASSWORD = "password";
    private static final Log log = LogFactory.getLog(AzureSecretCallbackHandler.class);
    private static String keyStorePassword;
    private static String privateKeyPassword;

    /**
     * Handles single secret callback.
     *
     * @param singleSecretCallback a single secret callback.
     */
    @Override
    protected void handleSingleSecretCallback(SingleSecretCallback singleSecretCallback) {

        if (keyStorePassword == null && privateKeyPassword == null) {
            boolean sameKeyAndKeyStorePass = true;
            String keyPassword = System.getProperty(KEY + DOT + PASSWORD);

            if (keyPassword != null && keyPassword.trim().equals("true")) {
                sameKeyAndKeyStorePass = false;
            }

            try {
                readPasswordFromKeyVault(sameKeyAndKeyStorePass);
            } catch (AzureSecretRepositoryException | ResourceNotFoundException e) {
                log.error("Building secret client failed: ", e);
            }
            readPasswordThroughConsole(sameKeyAndKeyStorePass);
        }

        if (singleSecretCallback.getId().equals(IDENTITY + DOT + KEY + DOT + PASSWORD)) {
            singleSecretCallback.setSecret(privateKeyPassword);
        } else {
            singleSecretCallback.setSecret(keyStorePassword);
        }
    }

    /**
     * Reads keystore and primary key passwords from Azure Key Vault.
     *
     * @param sameKeyAndKeyStorePass flag to indicate whether the keystore and primary key passwords are the same.
     * @throws AzureSecretRepositoryException if building a secret client fails.
     */
    private void readPasswordFromKeyVault(boolean sameKeyAndKeyStorePass) {

        if (log.isDebugEnabled()) {
            log.debug("Reading Carbon Secure Vault configuration properties from file.");
        }

        Properties properties = ConfigUtils.getConfigProperties();

        AzureSecretRepository azureSecretRepository = new AzureSecretRepository(null, null);
        azureSecretRepository.init(properties, HANDLER);

        String keyStoreAlias = properties.getProperty(KEY + STORE + DOT + IDENTITY + DOT + STORE + DOT + ALIAS);
        String privateKeyAlias = properties.getProperty(KEY + STORE + DOT + IDENTITY + DOT + KEY + DOT + ALIAS);

        keyStorePassword = azureSecretRepository.retrieveSecretFromVault(keyStoreAlias);
        if (sameKeyAndKeyStorePass) {
            privateKeyPassword = keyStorePassword;
        } else {
            privateKeyPassword = azureSecretRepository.retrieveSecretFromVault(privateKeyAlias);
        }
    }

    /**
     * Reads keystore and primary key passwords through the console if they could not be retrieved from the Key Vault.
     *
     * @param sameKeyAndKeyStorePass flag to indicate whether the keystore and primary key passwords are the same.
     */
    private void readPasswordThroughConsole(boolean sameKeyAndKeyStorePass) {

        if (StringUtils.isEmpty(keyStorePassword)) {

            if (log.isDebugEnabled()) {
                log.debug("Retrieval of keystore and private key password from Azure Key Vault failed.");
            }

            Console console;
            char[] password;

            if (sameKeyAndKeyStorePass) {
                if ((console = System.console()) != null && (password = console.readPassword("[%s]",
                        "Enter KeyStore and Private Key Password: ")) != null) {
                    keyStorePassword = String.valueOf(password);
                    privateKeyPassword = keyStorePassword;
                }
            } else {
                if ((console = System.console()) != null && (password = console.readPassword("[%s]",
                        "Enter KeyStore Password:")) != null) {
                    keyStorePassword = String.valueOf(password);
                }

                if ((console = System.console()) != null &&
                        (password = console.readPassword("[%s]",
                                "Enter Private Key Password: ")) != null) {
                    privateKeyPassword = String.valueOf(password);
                }
            }
        }
    }
}
