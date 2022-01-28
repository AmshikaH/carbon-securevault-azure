package org.wso2.carbon.securevault.azure;

import com.azure.identity.AzureCliCredential;
import com.azure.identity.AzureCliCredentialBuilder;
import com.azure.identity.ChainedTokenCredential;
import com.azure.identity.ChainedTokenCredentialBuilder;
import com.azure.identity.EnvironmentCredential;
import com.azure.identity.EnvironmentCredentialBuilder;
import com.azure.identity.ManagedIdentityCredential;
import com.azure.identity.ManagedIdentityCredentialBuilder;
import com.azure.security.keyvault.secrets.SecretClient;
import com.azure.security.keyvault.secrets.SecretClientBuilder;
import com.azure.security.keyvault.secrets.models.KeyVaultSecret;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.securevault.secret.SecretRepository;
import java.util.Properties;

/**
 * Extension to facilitate the use of an Azure Key Vault as an external secret repository.
 */
public class AzureKeyVaultRepository implements SecretRepository {

    // Log object used to add debug logging to the code
    private static final Log log = LogFactory.getLog(AzureKeyVaultRepository.class);
    // Strings used to build the property keys
    private static final String SECRET_REPOSITORIES = "secretRepositories";
    private static final String SECRET_PROVIDERS = "secretProviders";
    private static final String VAULT = "vault";
    private static final String PROPERTIES = "properties";
    private static final String REPOSITORIES = "repositories";
    private static final String AZURE = "azure";
    private static final String DOT = ".";
    // The name of the property for the Azure Key Vault's name
    private static final String KEY_VAULT_NAME = "keyVaultName";
    // The name of the property for the client id of a user-assigned managed identity
    private static final String MANAGED_IDENTITY_CLIENT_ID = "managedIdentityClientId";
    // The name of the environment variable for the client id of a user-assigned managed identity
    private static final String ENV_MI_CLIENT_ID = "MI_CLIENT_ID";
    // Strings used to build the Azure Key Vault's URI
    private static final String HTTPS_COLON_DOUBLE_SLASH = "https://";
    private static final String NET = "net";
    // String to store the name of the key vault read from the configuration file
    private String keyVaultName;
    // String to store the client id of the user-assigned managed identity (if used) read from the configuration file
    private String managedIdentityClientId;
    // Secret Client used to retrieve secrets from Azure Key Vault
    private SecretClient secretClient;

    /**
     * Initializes the Azure Key Vault as a Secret Repository by providing configuration properties.
     *
     * @param properties Configuration properties
     * @param id         Identifier to identify properties related to the corresponding repository
     */
    @Override
    public void init(Properties properties, String id) {
        if (log.isDebugEnabled()) {
            log.debug("Initializing Azure Key Vault connection.");
        }
        readProperties(properties);
        if (StringUtils.isEmpty(managedIdentityClientId)) {
            if (log.isDebugEnabled()) {
                log.debug("Managed identity clientId not found in configuration file. Checking environment variables.");
            }
            managedIdentityClientId = System.getenv(ENV_MI_CLIENT_ID);
            if (StringUtils.isEmpty(managedIdentityClientId) && log.isDebugEnabled()) {
                log.debug("Managed identity clientId not found in environment variables. Value set to null.");
            }
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Managed identity clientId found in configuration file. Using configured value.");
            }
        }
        String keyVaultUri = HTTPS_COLON_DOUBLE_SLASH + keyVaultName + DOT + VAULT + DOT + AZURE + DOT + NET;
        secretClient = new SecretClientBuilder()
                .vaultUrl(keyVaultUri)
                .credential(createAuthenticationChain())
                .buildClient();
    }

    /**
     * Retrieves the secret from the Azure Key Vault.
     *
     * @param alias The name and version (the latter is optional) of the secret being retrieved.
     * @return The secret corresponding to the alias from the Azure Key Vault. If not found, returns alias itself.
     */
    @Override
    public String getSecret(String alias) {
        if (StringUtils.isEmpty(keyVaultName)) {
            if (log.isDebugEnabled()) {
                log.debug("Azure key vault name cannot be null. Returning alias itself.");
            }
            return alias;
        }
        String secret = retrieveSecretFromVault(alias);
        if (StringUtils.isEmpty(secret)) {
            if (log.isDebugEnabled()) {
                log.debug("Could not find secret with alias '" + alias + "'. Returning alias itself.");
            }
            return alias;
        } else {
            return secret;
        }
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
     * Reads Carbon Secure Vault configuration properties.
     *
     * @param properties Configuration properties
     */
    private void readProperties(Properties properties) {
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
        String propertyKeyVaultName = novelFlag ? (novelPropertyPrefix + KEY_VAULT_NAME) :
                (legacyPropertyPrefix + KEY_VAULT_NAME);
        String propertyManagedIdentityClientID = novelFlag ? (novelPropertyPrefix + MANAGED_IDENTITY_CLIENT_ID) :
                (legacyPropertyPrefix + MANAGED_IDENTITY_CLIENT_ID);
        keyVaultName = properties.getProperty(propertyKeyVaultName);
        managedIdentityClientId = properties.getProperty(propertyManagedIdentityClientID);
    }

    /**
     * Retrieves the secret according to the specified version.
     * If a secret version has not been specified, the latest version is retrieved.
     *
     * @param alias The name and version (the latter is optional) of the secret being retrieved.
     * @return The secret corresponding to the alias from the Azure Key Vault.
     */
    private String retrieveSecretFromVault(String alias) {
        String secretName = alias;
        String secretVersion = "";
        if (alias.contains("_")) {
            int underscoreIndex = alias.indexOf("_");
            secretName = alias.substring(0, underscoreIndex);
            secretVersion = alias.substring(underscoreIndex + 1);
            if (log.isDebugEnabled()) {
                log.debug("Secret version found in alias. Retrieving the specified version of secret.");
            }
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Secret version not specified in alias. Checking environment variables.");
            }
            secretVersion = System.getenv(alias);
            if (StringUtils.isEmpty(secretVersion) && log.isDebugEnabled()) {
                log.debug("Secret version not found in environment variables. Retrieving latest version of secret.");
            }
        }
        KeyVaultSecret retrievedSecret = secretClient.getSecret(secretName, secretVersion);
        String secret = retrievedSecret.getValue();
        return secret;
    }

    /**
     * Creates a credential chain which attempts to authenticate to the Azure Key Vault via environment credentials,
     * a managed identity or the Azure CLI in order. If none are available, authentication fails.
     *
     * @return The credential chain mentioned above.
     *
     */
    private ChainedTokenCredential createAuthenticationChain() {
        EnvironmentCredential environmentCredential = new EnvironmentCredentialBuilder()
                .build();
        ManagedIdentityCredential managedIdentityCredential = new ManagedIdentityCredentialBuilder()
                .clientId(managedIdentityClientId)
                .build();
        AzureCliCredential azureCliCredential = new AzureCliCredentialBuilder().
                build();
        ChainedTokenCredential credentialChain = new ChainedTokenCredentialBuilder()
                .addFirst(environmentCredential)
                .addLast(managedIdentityCredential)
                .addLast(azureCliCredential)
                .build();
        return  credentialChain;
    }
}