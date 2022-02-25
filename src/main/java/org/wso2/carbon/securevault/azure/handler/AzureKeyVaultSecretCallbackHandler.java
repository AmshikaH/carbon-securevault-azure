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

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.securevault.azure.exception.AzureKeyVaultException;
import org.wso2.carbon.securevault.azure.repository.AzureKeyVaultRepository;
import org.wso2.carbon.utils.CarbonUtils;
import org.wso2.securevault.SecureVaultException;
import org.wso2.securevault.secret.AbstractSecretCallbackHandler;
import org.wso2.securevault.secret.SingleSecretCallback;

import java.io.Console;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

import static org.wso2.carbon.securevault.azure.common.AzureKeyVaultConstants.DOT;
import static org.wso2.carbon.securevault.azure.common.AzureKeyVaultConstants.IDENTITY;
import static org.wso2.carbon.securevault.azure.common.AzureKeyVaultConstants.KEY;
import static org.wso2.carbon.securevault.azure.common.AzureKeyVaultConstants.REGEX;
import static org.wso2.carbon.securevault.azure.common.AzureKeyVaultConstants.STORE;

/**
 * Secret Callback handler class if keystore and primary key passwords are stored in the
 * Azure Key Vault that stores the deployment secrets.
 */
public class AzureKeyVaultSecretCallbackHandler extends AbstractSecretCallbackHandler {

    private static final String ALIAS = "alias";
    private static final String CONFIG_FILE_PATH = CarbonUtils.getCarbonConfigDirPath() + File.separator +
            "security" + File.separator + "secret-conf.properties";
    private static final String PASSWORD = "password";
    private static final Log log = LogFactory.getLog(AzureKeyVaultSecretCallbackHandler.class);
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
            } catch (AzureKeyVaultException e) {
                log.error(e.getMessage().replaceAll(REGEX, ""));
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
     */
    @SuppressFBWarnings("PATH_TRAVERSAL_IN")
    private void readPasswordFromKeyVault(boolean sameKeyAndKeyStorePass) throws AzureKeyVaultException {

        if (log.isDebugEnabled()) {
            log.debug("Reading Carbon Secure Vault configuration properties from file.");
        }

        InputStream inputStream = null;
        Properties properties = new Properties();

        try {
            inputStream = new FileInputStream(CONFIG_FILE_PATH);
            properties.load(inputStream);
        } catch (Exception e) {
            throw new SecureVaultException("Error while loading configurations from " + CONFIG_FILE_PATH, e);
        } finally {
            try {
                if (inputStream != null) {
                    inputStream.close();
                }
            } catch (IOException e) {
                log.warn("Error closing input stream of configuration file.");
            }
        }

        AzureKeyVaultRepository.buildSecretClient(properties);
        AzureKeyVaultRepository azureKeyVaultRepository = new AzureKeyVaultRepository();

        String keyStoreAlias = properties.getProperty(KEY + STORE + DOT + IDENTITY + DOT + STORE + DOT + ALIAS);
        String privateKeyAlias = properties.getProperty(KEY + STORE + DOT + IDENTITY + DOT + KEY + DOT + ALIAS);

        keyStorePassword = azureKeyVaultRepository.getSecret(keyStoreAlias);
        if (sameKeyAndKeyStorePass) {
            privateKeyPassword = keyStorePassword;
        } else {
            privateKeyPassword = azureKeyVaultRepository.getSecret(privateKeyAlias);
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
