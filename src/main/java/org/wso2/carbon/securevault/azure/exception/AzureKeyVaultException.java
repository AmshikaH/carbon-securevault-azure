package org.wso2.carbon.securevault.azure.exception;

/**
 * The exception thrown when the Azure Key Vault configurations have not been set properly.
 */
public class AzureKeyVaultException extends Exception {
    public AzureKeyVaultException(String message) {
        super(message);
    }

    public AzureKeyVaultException(String message, Throwable cause) {
        super(message, cause);
    }
}
