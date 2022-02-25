package org.wso2.carbon.securevault.azure.exception;

/**
 * Azure Key Vault exception.
 */
public class AzureKeyVaultException extends Exception {
    public AzureKeyVaultException(String message) {
        super(message);
    }

    public AzureKeyVaultException(String message, Throwable cause) {
        super(message, cause);
    }
}
