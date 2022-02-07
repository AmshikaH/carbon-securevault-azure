# Carbon Secure Vault Extension for Azure Key Vault

## Step 1: Building and Inserting the Azure Extension into the Identity Server

1. Clone this project onto your computer or download it as a zip.
2. Run `mvn clean install` from the carbon-securevault-azure directory to build the OSGi bundle for the extension.
3. Copy this bundle from the target directory within the project.
4. Insert the bundle within the Identity Server by pasting it into the <IS_HOME>/repository/components/dropins directory.

## Step 2: Enabling Carbon Secure Vault

Add the following lines to the Carbon Secure Vault configuration file `secret-conf.properties`  [<IS_HOME>/repository/conf/security/secret-conf.properties].

```
keystore.identity.location=repository/resources/security/wso2carbon.jks
keystore.identity.type=JKS
keystore.identity.store.password=identity.store.password
keystore.identity.store.secretProvider=org.wso2.carbon.securevault.DefaultSecretCallbackHandler
keystore.identity.key.password=identity.key.password
keystore.identity.key.secretProvider=org.wso2.carbon.securevault.DefaultSecretCallbackHandler
carbon.secretProvider=org.wso2.securevault.secret.handler.SecretManagerSecretCallbackHandler
secVault.enabled=true

secretRepositories=vault
secretRepositories.vault.provider=org.wso2.carbon.securevault.azure.AzureKeyVaultRepositoryProvider
secretRepositories.vault.properties.keyVaultName=<name-of-the-azure-key-vault>
secretProviders.vault.repositories.azure.properties.managedIdentityClientId=<client-id-of-user-assigned-managed-identity>
```

The last two lines above are properties that need to be edited according to the user's vault;
- secretRepositories.vault.properties.keyVaultName: the name of the Azure Key Vault which is to be used as a secret repository.
- [optional] secretProviders.vault.repositories.azure.properties.managedIdentityClientId: if authentication to the Azure Key Vault is to be done via a user-assigned managed identity, the client id of this identity. You may also choose to set this value as an environment variable named “MI_CLIENT_ID” instead of adding it here.

## Step 3: Referencing Deployment Secrets

1. In the deployment.toml file (<IS_HOME>/repository/conf/deployment.toml), replace each value to be stored as a secret with a reference.

   - To retrieve the latest version of a secret: set the reference using an alias in the format `$secret{alias}`, where the alias is the name of the secret in your Key Vault.

     Example:
     ```
     [super_admin]
     username = "admin"
     password = "admin"
     create_admin_account = true
     ```

     The password in the above could be stored in the user's Key Vault as a secret with the name "admin-password". Then the configuration would be updated as follows.

     ```
     [super_admin]
     username = "admin"
     password = "$secret{admin-password}"
     create_admin_account = true
     ```

   - To retrieve a specific version of a secret, set the reference in the format `$secret{alias_version}`.

2. This step differs depending on your version of the Identity Server.
   
   **Version 5.11.0 and below:**
   
   Add the following lines to the deployment.toml file.
   ```
   [secrets]
   alias1 = ""
   alias2 = ""
   alias3 = ""
   ```

   Based on the example given in the previous step, it would be as follows.
   ```
   [secrets]
   admin-password = “”
   ```

   **Version 5.12.0 onwards:**
   
   Add the following lines to the deployment.toml file.
   ```
   [runtime_secrets]
   enable = "true"
   ```

## Step 4: Setting Up Authentication to Azure Key Vault

An authentication chain has been used to allow you the flexibility to choose your preferred way. The authentication chain supports authentication via [environment variables](https://docs.microsoft.com/en-us/azure/developer/java/sdk/identity-azure-hosted-auth#environment-variables), [managed identities](https://docs.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/overview) or the [Azure CLI](https://docs.microsoft.com/en-us/azure/developer/java/sdk/identity-dev-env-auth#azure-cli-credential).

If you choose to authenticate via a user-assigned managed identity, see [Step 2: Enabling Carbon Secure Vault](#step-2-enabling-carbon-secure-vault) above regarding setting the managed identity's client id.

## Step 5: Carbon Secure Vault Root Password

When you start the server, you will be required to provide the keystore and private key password.

You may do this in one of the following ways.
1) Enter the value for this in the command line.
2) Store the value in a file within the Identity Server which will be read upon deployment.
3) Store the value within your Azure Key Vault which will be read upon deployment.

### 1. Entering in the Command Line

If neither of the other options have been configured, you will be prompted to enter the keystore and private key password, where you may then enter it manually.

`[Enter KeyStore and Private Key Password :]`

However, this is not possible when you run the server as a background task, such as when it's hosted in the cloud, so we could instead save the value elsewhere and have it automatically read as mentioned in methods 2 and 3.

### 2. Storing in a file within the Identity Server

Create a file containing the password in the <IS_HOME> directory and name it as described below.

- If you wish to have the file deleted automatically after the server starts, the file name will have `tmp` (i.e., temporary) in it as follows.

  > For Linux: The file name should be `password-tmp`.
  >
  > For Windows: The file name should be `password-tmp.txt`.

- Alternatively, if you wish to retain the password file after the server starts so that the same file can be used in subsequent deployments as well, the file name will have `persist` (i.e., persistent) as follows.

  >For Linux: The file name should be `password-persist`.
  >
  >For Windows: The file name should be `password-persist.txt`.

Note that, by default, both the private key and keystore passwords are assumed to be the same. However, if they are not the same, the private key password must be entered in the second line of the file.

### 3. Storing within your Key Vault

1. Create a secret and store your password(s) in your Vault.
2. Edit the configurations in the secret-conf.properties file () mentioned in step 2 as follows.
   1. Replace the values for the two properties `keystore.identity.store.secretProvider` and `keystore.identity.key.secretProvider` with `org.wso2.carbon.securevault.azure.AzureKeyVaultSecretCallbackHandler`. This is the fully qualified class path of the AzureKeyVaultSecretCallbackHandler, which we will be using instead of the DefaultSecretCallbackHandler.
   2. Provide the alias and version of your password(s) in the format `alias_version` as below. If only the alias is given, the latest version of the secret will be retrieved.
        ```
        keystore.identity.store.alias=<alias-and-version-of-password>
        keystore.identity.key.alias=<alias-and-version-of-password>
        ```
        If both the keystore and private key passwords are the same, only provide the keystore password (the first line). However, if they are not, provide the alias and version of the private key password as well.

Your configuration would now be as follows.
```
keystore.identity.location=repository/resources/security/wso2carbon.jks
keystore.identity.type=JKS
keystore.identity.store.password=identity.store.password
keystore.identity.store.alias=<alias-and-version-of-password>
keystore.identity.store.secretProvider=org.wso2.carbon.securevault.azure.AzureKeyVaultSecretCallbackHandler
keystore.identity.key.password=identity.key.password
keystore.identity.key.secretProvider=org.wso2.carbon.securevault.azure.AzureKeyVaultSecretCallbackHandler
keystore.identity.key.alias=<alias-and-version-of-password>
carbon.secretProvider=org.wso2.securevault.secret.handler.SecretManagerSecretCallbackHandler
secVault.enabled=true

secretRepositories=vault
secretRepositories.vault.provider=org.wso2.carbon.securevault.azure.AzureKeyVaultRepositoryProvider
secretRepositories.vault.properties.keyVaultName=<name-of-the-azure-key-vault>
secretProviders.vault.repositories.azure.properties.managedIdentityClientId=<client-id-of-user-assigned-managed-identity>
```
## Debugging

1. For debug logs, add the following lines to the log4j2.properties file (<IS_HOME>\repository\conf\log4j2.properties).

   ```
   logger.org-wso2-carbon-securevault-azure.name=org.wso2.carbon.securevault.azure
   logger.org-wso2-carbon-securevault-azure.level=DEBUG
   logger.org-wso2-carbon-securevault-azure.additivity=false
   logger.org-wso2-carbon-securevault-azure.appenderRef.CARBON_CONSOLE.ref = CARBON_CONSOLE
   ```

2. Then add “org-wso2-carbon-securevault-azure” to the list of loggers as follows.

   ```
   loggers = AUDIT_LOG, trace-messages, ..., org-wso2-carbon-securevault-azure
   ```
