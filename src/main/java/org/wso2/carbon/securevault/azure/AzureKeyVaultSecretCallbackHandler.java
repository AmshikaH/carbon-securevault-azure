package org.wso2.carbon.securevault.azure;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.securevault.SecureVaultException;
import org.wso2.securevault.secret.AbstractSecretCallbackHandler;
import org.wso2.securevault.secret.SingleSecretCallback;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

import static org.wso2.carbon.securevault.azure.AzureKeyVaultConstants.ALIAS;
import static org.wso2.carbon.securevault.azure.AzureKeyVaultConstants.CONFIG_FILE_PATH;
import static org.wso2.carbon.securevault.azure.AzureKeyVaultConstants.DOT;
import static org.wso2.carbon.securevault.azure.AzureKeyVaultConstants.IDENTITY;
import static org.wso2.carbon.securevault.azure.AzureKeyVaultConstants.KEY;
import static org.wso2.carbon.securevault.azure.AzureKeyVaultConstants.PASSWORD;
import static org.wso2.carbon.securevault.azure.AzureKeyVaultConstants.STORE;

/**
 * Secret Callback handler class if keystore and primary key passwords are stored in the
 * Azure Key Vault that stores the deployment secrets.
 */
public class AzureKeyVaultSecretCallbackHandler extends AbstractSecretCallbackHandler {

    private static final Log log = LogFactory.getLog(AzureKeyVaultSecretCallbackHandler.class);
    private static String keyStorePassword;
    private static String privateKeyPassword;

    /**
     * Handles single secret callback.
     *
     * @param singleSecretCallback a single secret callback
     */
    @Override
    protected void handleSingleSecretCallback(SingleSecretCallback singleSecretCallback) {
        if (keyStorePassword == null && privateKeyPassword == null) {
            boolean sameKeyAndKeyStorePass = true;
            String keyPassword = System.getProperty(KEY + DOT + PASSWORD);
            if (keyPassword != null && keyPassword.trim().equals("true")) {
                sameKeyAndKeyStorePass = false;
            }
            readPassword(sameKeyAndKeyStorePass);
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
     * @param sameKeyAndKeyStorePass flag to indicate whether the keystore and primary key passwords are the same
     */
    private void readPassword(boolean sameKeyAndKeyStorePass) {
        if (log.isDebugEnabled()) {
            log.debug("Reading configuration properties from file.");
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
                log.warn("Error closing input stream of configuration file");
            }
        }
        AzureKeyVaultRepository.authenticateToKeyVault(properties);
        AzureKeyVaultRepository azureKeyVaultRepository = new AzureKeyVaultRepository();
        String keyStoreAlias = properties.getProperty(KEY + STORE + DOT + IDENTITY + DOT + STORE + DOT + ALIAS);
        String privateKeyAlias = properties.getProperty(KEY + STORE + DOT + IDENTITY + KEY + STORE + DOT + ALIAS);
        keyStorePassword = azureKeyVaultRepository.getSecret(keyStoreAlias);
        if (sameKeyAndKeyStorePass) {
            privateKeyPassword = keyStorePassword;
        } else {
            privateKeyPassword = azureKeyVaultRepository.getSecret(privateKeyAlias);
        }
    }
}
