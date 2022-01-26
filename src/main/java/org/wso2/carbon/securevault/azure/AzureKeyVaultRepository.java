package org.wso2.carbon.securevault.azure;

import com.azure.identity.DefaultAzureCredentialBuilder;
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

        String legacyPropertyPrefix = SECRET_REPOSITORIES + DOT + VAULT + DOT + PROPERTIES + DOT;
        String novelPropertyPrefix = SECRET_PROVIDERS + DOT + VAULT + DOT + REPOSITORIES + DOT +
                AZURE + PROPERTIES + DOT;

        boolean novelFlag = readProviders(properties);
        String propertyKeyVaultName = novelFlag ? (novelPropertyPrefix + KEY_VAULT_NAME) :
                (legacyPropertyPrefix + KEY_VAULT_NAME);
        String propertyManagedIdentityClientID = novelFlag ? (novelPropertyPrefix + MANAGED_IDENTITY_CLIENT_ID) :
                (legacyPropertyPrefix + MANAGED_IDENTITY_CLIENT_ID);

        keyVaultName = properties.getProperty(propertyKeyVaultName);
        managedIdentityClientId = properties.getProperty(propertyManagedIdentityClientID);

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
    }

    /**
     * Initializes the Azure Key Vault as a Repository by providing configuration properties.
     *
     * @param alias The name of the secret being retrieved
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

        String keyVaultUri = HTTPS_COLON_DOUBLE_SLASH + keyVaultName + DOT + VAULT + DOT + AZURE + DOT + NET;

        SecretClient secretClient = new SecretClientBuilder()
                .vaultUrl(keyVaultUri)
                .credential(new DefaultAzureCredentialBuilder().
                        managedIdentityClientId(managedIdentityClientId).build())
                .buildClient();

        KeyVaultSecret retrievedSecret = secretClient.getSecret(alias);
        String secret = retrievedSecret.getValue();
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

    private boolean readProviders(Properties properties) {
        String legacyProvidersString = properties.getProperty("secretRepositories", null);
        if (StringUtils.isEmpty(legacyProvidersString)) {
            if (log.isDebugEnabled()) {
                log.debug("Legacy provider not found. Using novel configurations.");
            }
            return true;
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Legacy provider found. Using legacy configurations.");
            }
            return false;
        }
    }
}
