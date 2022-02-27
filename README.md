# Carbon Secure Vault Extension for Azure Key Vault

Carbon Secure Vault extension to use Azure Key Vault as an external secret repository.

## Step 1: Building and Inserting the Azure Extension into the Identity Server

1. Clone this project onto your computer or download it as a zip.
2. Run `mvn clean install` from the carbon-securevault-azure directory to build the OSGi bundle for the extension.
3. Copy this bundle from the target directory within the project.
4. Insert the bundle within the Identity Server by pasting it into the `dropins` directory (`<IS_HOME>/repository/components/dropins`).

## Step 2: Enabling Carbon Secure Vault

There are 2 ways of configuring the secret repository. Namely, the legacy and novel configurations.

The novel configuration can be used only from Identity Server 5.12.0 onwards, while the legacy configuration can be used with any version.

First, add the following lines to the `secret-conf.properties` Carbon Secure Vault configuration file (`<IS_HOME>/repository/conf/security/secret-conf.properties`).

```
keystore.identity.location=repository/resources/security/wso2carbon.jks
keystore.identity.type=JKS
keystore.identity.store.password=identity.store.password
keystore.identity.store.secretProvider=org.wso2.carbon.securevault.DefaultSecretCallbackHandler
keystore.identity.key.password=identity.key.password
keystore.identity.key.secretProvider=org.wso2.carbon.securevault.DefaultSecretCallbackHandler
carbon.secretProvider=org.wso2.securevault.secret.handler.SecretManagerSecretCallbackHandler
secVault.enabled=true
```

Then, add the next set of configurations as given below depending on whether you are using the legacy or novel configurations.

1. Legacy:

   ```
   secretRepositories=vault
   secretRepositories.vault.provider=org.wso2.carbon.securevault.azure.repository.AzureKeyVaultRepositoryProvider
   secretRepositories.vault.properties.keyVaultName=<name-of-the-azure-key-vault>
   secretRepositories.vault.properties.credential=<choice-of-authentication-credential>
   secretRepositories.vault.properties.managedIdentityClientId=<client-id-of-user-assigned-managed-identity>
   ```

2. Novel:

   ```
   secretProviders=vault
   secretProviders.vault.provider=org.wso2.securevault.secret.repository.VaultSecretRepositoryProvider
   secretProviders.vault.repositories=azure
   secretProviders.vault.repositories.azure=org.wso2.carbon.securevault.azure.repository.AzureKeyVaultRepository
   secretProviders.vault.repositories.azure.properties.keyVaultName=<name-of-the-azure-key-vault>
   secretProviders.vault.repositories.azure.properties.credential=<choice-of-authentication-credential>
   secretProviders.vault.repositories.azure.properties.managedIdentityClientId=<client-id-of-user-assigned-managed-identity>
   ```

The last three lines of both configurations are properties that need to be edited according to the user's vault and authentication preference;
- `keyVaultName`: the name of the Key Vault which is to be used as a secret repository. You may also choose to set this value as an environment variable named `KV_NAME` instead of adding it here.
- `credential`: the credential you wish to use to authenticate to the Key Vault. You may also choose to set this value as an environment variable named `CREDENTIAL` instead of adding it here. See [Step 4: Setting Up Authentication to Azure Key Vault](#step-4-setting-up-authentication-to-azure-key-vault) for further details.
- (optional) `managedIdentityClientId`: if authentication to the Key Vault is to be done via a user-assigned managed identity, the client id of this identity. You may also choose to set this value as an environment variable named `MI_CLIENT_ID` instead of adding it here.

***Note that in all 3 cases above, if the value has been set in the configuration file and as an environment variable, the value set in the configuration file is given priority and will be the one that is used.***

## Step 3: Referencing Deployment Secrets

1. In the `deployment.toml` file (`<IS_HOME>/repository/conf/deployment.toml`), replace each value to be stored as a secret with a reference.

    - To retrieve the latest version of a secret: set the reference using an alias in the format `$secret{alias}`, where the alias is the name of the secret in your Key Vault.

      Example:
      ```
      [super_admin]
      username = "admin"
      password = "admin"
      create_admin_account = true
      ```

      The password in the above could be stored in the user's Key Vault as a secret with the name `admin-password`. Then the configuration would be updated as follows.

      ```
      [super_admin]
      username = "admin"
      password = "$secret{admin-password}"
      create_admin_account = true
      ```

    - To retrieve a specific version of a secret, set the reference in the format `$secret{alias_version}`.

2. This step differs depending on your version of the Identity Server.

   **Version 5.11.0 and below:**

   Add the following lines to the `deployment.toml` file.
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

   Add the following lines to the `deployment.toml` file.
   ```
   [runtime_secrets]
   enable = "true"
   ```

## Step 4: Setting Up Authentication to Azure Key Vault

You have 3 choices for the authentication credential you wish to use, and it is necessary to specify your choice either as a configuration property or an environment variable.

1. [Environment Variables](https://docs.microsoft.com/en-us/azure/developer/java/sdk/identity-azure-hosted-auth#environment-variables) - value must be set to `env`
2. [Managed Identities](https://docs.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/overview) - value must be set to `mi`
3. [Azure CLI](https://docs.microsoft.com/en-us/azure/developer/java/sdk/identity-dev-env-auth#azure-cli-credential) - value must be set to `cli`
4. [The Default Azure Credential Chain](https://docs.microsoft.com/en-us/azure/developer/java/sdk/identity-azure-hosted-auth#default-azure-credential) - value must be set to `chain`

   The Default Azure Credential Chain supports authentication through environment variables, managed identities, IDE-specific credentials and the Azure CLI in the given order.

Example:

- Configuring option 1 as a property in the configuration file (see [Step 2: Enabling Carbon Secure Vault](#step-2-enabling-carbon-secure-vault)):

  Legacy:
   ```
   secretRepositories.vault.properties.credential=env
   ```

  Novel:
   ```
   secretProviders.vault.repositories.azure.properties.credential=env
   ```
  
- Alternatively, you could set it as an environment variable named `CREDENTIAL`:

   ```
   CREDENTIAL=env
   ```

Optional: If you choose to authenticate via a user-assigned managed identity, the managed identity's client id can be set in the same manner, i.e., as a configuration property or an environment variable named `MI_CLIENT_ID`.

## Step 5: Carbon Secure Vault Root Password

When you start the server, you will be required to provide the keystore and private key password.

You may do this in one of the following ways.
1. Enter the value for this in the command line.
2. Store the value in a file within the Identity Server which will be read upon deployment.
3. Store the value within your Azure Key Vault which will be read upon deployment.

### 1. Entering in the Command Line

If neither of the other options have been configured, you will be prompted to enter the keystore and private key password, where you may then enter it manually.

`[Enter KeyStore and Private Key Password: ]`

However, this is not possible when you run the server as a background task, such as when it's hosted in the cloud, so we could instead save the value elsewhere and have it automatically read as mentioned in methods 2 and 3.

### 2. Storing in a file within the Identity Server

Create a file containing the password in the `<IS_HOME>` directory and name it as described below.

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

1. Create a secret and store your password(s) in your Key Vault.
2. Edit the configurations in the `secret-conf.properties` file mentioned in [Step 2: Enabling Carbon Secure Vault](#step-2-enabling-carbon-secure-vault) as follows.
    1. Replace the values for the two properties `keystore.identity.store.secretProvider` and `keystore.identity.key.secretProvider` with `org.wso2.carbon.securevault.azure.handler.AzureKeyVaultSecretCallbackHandler`. This is the fully qualified class path of the Azure Key Vault Secret Callback Handler, which we will be using instead of the Default Secret Callback Handler.
    2. Provide the alias and version of your password(s) in the format `alias_version` as below. If only the alias is given, the latest version of the secret will be retrieved.
         ```
         keystore.identity.store.alias=<alias-and-version-of-password>
         keystore.identity.key.alias=<alias-and-version-of-password>
         ```
       If both the keystore and private key passwords are the same, only provide the keystore password (the first line). However, if they are not, provide the alias and version of the private key password as well.

The first half of your configuration file would now be as follows. Note that no changes are required to the second half of your file.
```
keystore.identity.location=repository/resources/security/wso2carbon.jks
keystore.identity.type=JKS
keystore.identity.store.password=identity.store.password
keystore.identity.store.alias=<alias-and-version-of-password>
keystore.identity.store.secretProvider=org.wso2.carbon.securevault.azure.handler.AzureKeyVaultSecretCallbackHandler
keystore.identity.key.password=identity.key.password
keystore.identity.key.secretProvider=org.wso2.carbon.securevault.azure.handler.AzureKeyVaultSecretCallbackHandler
keystore.identity.key.alias=<alias-and-version-of-password>
carbon.secretProvider=org.wso2.securevault.secret.handler.SecretManagerSecretCallbackHandler
secVault.enabled=true
```

## Using an Azure Key Vault with Other Repositories

The use of multiple secret repositories is only supported from WSO2 Identity Server version 5.12.0 onwards with the novel configurations mentioned in [Step 2: Enabling Carbon Secure Vault](#step-2-enabling-carbon-secure-vault) edited as follows.

   ```
   secretProviders=vault
   secretProviders.vault.provider=org.wso2.securevault.secret.repository.VaultSecretRepositoryProvider
   secretProviders.vault.repositories=azure,<other-repository-type>
   secretProviders.vault.repositories.azure=org.wso2.carbon.securevault.azure.repository.AzureKeyVaultRepository
   secretProviders.vault.repositories.azure.properties.keyVaultName=<name-of-the-azure-key-vault>
   secretProviders.vault.repositories.azure.properties.credential=<choice-of-authentication-credential>
   secretProviders.vault.repositories.azure.properties.managedIdentityClientId=<client-id-of-user-assigned-managed-identity>
   secretProviders.vault.repositories.<other-repository-type>=<fully-qualified-classpath-of-the-other-repository>
   secretProviders.vault.repositories.<other-repository-type>.properties.<property-name>=<property-value>
   ```

## Debugging

1. For debug logs, add the following lines to the `log4j2.properties` file (`<IS_HOME>\repository\conf\log4j2.properties`).

   ```
   logger.org-wso2-carbon-securevault-azure.name=org.wso2.carbon.securevault.azure
   logger.org-wso2-carbon-securevault-azure.level=DEBUG
   logger.org-wso2-carbon-securevault-azure.additivity=false
   logger.org-wso2-carbon-securevault-azure.appenderRef.CARBON_CONSOLE.ref = CARBON_CONSOLE
   ```

2. Then add `org-wso2-carbon-securevault-azure` to the list of loggers as follows.

   ```
   loggers = AUDIT_LOG, trace-messages, ..., org-wso2-carbon-securevault-azure
   ```
