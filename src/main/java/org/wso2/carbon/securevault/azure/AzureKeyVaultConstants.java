package org.wso2.carbon.securevault.azure;

import org.wso2.carbon.utils.CarbonUtils;

import java.io.File;

/**
 * Constants used in the extension.
 */
public class AzureKeyVaultConstants {
    public static final String ALIAS = "alias";
    public static final String AZURE = "azure";
    public static final String CONFIG_FILE_PATH = CarbonUtils.getCarbonConfigDirPath() + File.separator +
            "security" + File.separator + "secret-conf.properties";
    public static final String DOT = ".";
    public static final String ENV_MI_CLIENT_ID = "MI_CLIENT_ID";
    public static final String HTTPS_COLON_DOUBLE_SLASH = "https://";
    public static final String IDENTITY = "identity";
    public static final String KEY = "key";
    public static final String KEY_VAULT_NAME = "keyVaultName";
    public static final String MANAGED_IDENTITY_CLIENT_ID = "managedIdentityClientId";
    public static final String NET = "net";
    public static final String PASSWORD = "password";
    public static final String PROPERTIES = "properties";
    public static final String REPOSITORIES = "repositories";
    public static final String SECRET_CALLBACK_HANDLER =
            "org.wso2.carbon.securevault.azure.AzureKeyVaultSecretCallbackHandler";
    public static final String SECRET_PROVIDER = "secretProvider";
    public static final String SECRET_PROVIDERS = "secretProviders";
    public static final String SECRET_REPOSITORIES = "secretRepositories";
    public static final String STORE = "store";
    public static final String VAULT = "vault";
}
