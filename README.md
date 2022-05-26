# Carbon Secure Vault Extension for Azure Key Vault

Carbon Secure Vault extension to use an Azure Key Vault as an external secret repository.

## Step 1: Building and Inserting the Azure Extension into the Identity Server

1. Clone this project onto your computer or download it as a zip and unzip it.
2. Run `mvn clean install` from the `carbon-securevault-azure` directory to build the OSGi bundle for the extension.
3. Copy this bundle, the `org.wso2.carbon.securevault.azure-1.0.jar` file, from the `target` directory within the project.
4. Insert the bundle within the Identity Server by pasting it into the `dropins` directory (`<IS_HOME>/repository/components/dropins`).

## Step 2: Downloading and Inserting the Required Dependencies into the Identity Server

**Linux:**
1. Navigate to the `scripts` directory in a terminal window.
2. Run `bash get-dependencies.sh` to download the dependency jar files.
3. Copy all the jar files in the `scripts/dependencies` directory within the project.
4. Insert these dependencies within the Identity Server by pasting them into the `lib` directory (`<IS_HOME>/repository/components/dropins`).

**Windows:**
1. Navigate to the `scripts` directory.
2. Double-click on the `get-dependencies.bat` file to run the script and download the dependency jar files.
3. Copy all the jar files in the `scripts/dependencies` directory within the project.
4. Insert these dependencies within the Identity Server by pasting them into the `lib` directory (`<IS_HOME>/repository/components/dropins`).

## Step 3: Enabling Carbon Secure Vault

There are 2 ways of configuring the secret repository. Namely, the legacy and novel configuration.

The novel configuration was introduced in Identity Server 5.12.0 and the legacy configuration was used in lower versions. While Identity Server 5.12.0 still supports the legacy configuration, the novel configuration is the recommended method for reasons mentioned under the legacy configuration below.

1. Add the following lines to the `secret-conf.properties` Carbon Secure Vault configuration file (`<IS_HOME>/repository/conf/security/secret-conf.properties`) according to whether you are using the novel or legacy configuration.

    - **Novel (recommended for Identity Server 5.12.0 and above):**

      ```
      carbon.secretProvider=org.wso2.securevault.secret.handler.SecretManagerSecretCallbackHandler
      secVault.enabled=true
      secretProviders=vault
      secretProviders.vault.provider=org.wso2.securevault.secret.repository.VaultSecretRepositoryProvider
      secretProviders.vault.repositories=azure
      secretProviders.vault.repositories.azure=org.wso2.carbon.securevault.azure.repository.AzureSecretRepository
      secretProviders.vault.repositories.azure.properties.keyVaultName=<name-of-the-azure-key-vault>
      secretProviders.vault.repositories.azure.properties.credential=<choice-of-authentication-credential>
      secretProviders.vault.repositories.azure.properties.managedIdentityClientId=<client-id-of-user-assigned-managed-identity>
      ```

    - **Legacy:**

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
      secretRepositories.vault.provider=org.wso2.carbon.securevault.azure.repository.AzureSecretRepositoryProvider
      secretRepositories.vault.properties.keyVaultName=<name-of-the-azure-key-vault>
      secretRepositories.vault.properties.credential=<choice-of-authentication-credential>
      secretRepositories.vault.properties.managedIdentityClientId=<client-id-of-user-assigned-managed-identity>
      ```
      Note that the lines of keystore configuration given above are, in fact, for the keystore used with the default file-based secret repository of the Identity Server; this keystore isn't actually necessary for storing and retrieving secrets from a Key Vault. However, the legacy configuration requires the keystore to be configured for the initialization of any secret repository. This configuration of the keystore entails adding the lines that start with `keystore.identity` mentioned above and providing the keystore password as mentioned in [Step 5: Carbon Secure Vault Root Password](#step-5-carbon-secure-vault-root-password-for-legacy-configuration-only).

      Therefore, if you are using version 5.12.0 or above of the Identity Server, it is recommended to use the novel configuration instead of the legacy configuration.

2. Edit the last three lines of either configuration according to your Key Vault and authentication preference;
    - `keyVaultName`: the name of the Key Vault which is to be used as a secret repository. You may also choose to set this value as an environment variable named `KV_NAME` instead of adding it here.
    - `credential`: the credential you wish to use to authenticate to the Key Vault. You may also choose to set this value as an environment variable named `CREDENTIAL` instead of adding it here. See [Step 4: Setting Up Authentication to Azure Key Vault](#step-4-setting-up-authentication-to-azure-key-vault) for further details on the options available.
    - (optional) `managedIdentityClientId`: if authentication to the Key Vault is to be done via a user-assigned managed identity, the client id of this identity. You may also choose to set this value as an environment variable named `MI_CLIENT_ID` instead of adding it here.

**Note that in all 3 cases above, if the value has been set both in the configuration file and as an environment variable, the value set in the configuration file is given priority and will be the one that is used.**

## Step 4: Referencing Deployment Secrets

1. In the `deployment.toml` file (`<IS_HOME>/repository/conf/deployment.toml`), replace each value to be stored as a secret with a reference.

    - **To retrieve the latest version of a secret by default:** set the reference using an alias in the format `$secret{alias}`, where the alias is the name of the secret in your Key Vault.

      Example:
      ```
      [super_admin]
      username = "admin"
      password = "admin"
      create_admin_account = true
      ```

      If the password in the above is stored in the user's Key Vault as a secret with the name `admin-password`, the configuration would be updated as follows.

      ```
      [super_admin]
      username = "admin"
      password = "$secret{admin-password}"
      create_admin_account = true
      ```

    - **To retrieve a specific version of a secret:** set the reference in the format `$secret{alias_version}`.

2. This step differs depending on your version of the Identity Server.

    - **Version 5.12.0 onwards:**

      Add the following section to the `deployment.toml` file.
      ```
      [runtime_secrets]
      enable = "true"
      ```

    - **Versions below 5.12.0:**

      Add the following section to the `deployment.toml` file with a list of your aliases.
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


## Step 5: Setting Up Authentication to Azure Key Vault

You have 4 choices for the authentication credential you may use and it is necessary to specify your choice either as a configuration property or an environment variable.

1. [Environment Variables](https://docs.microsoft.com/en-us/azure/developer/java/sdk/identity-azure-hosted-auth#environment-variables) - value must be set to `env`
2. [Managed Identities](https://docs.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/overview) - value must be set to `mi`
3. [Azure CLI](https://docs.microsoft.com/en-us/azure/developer/java/sdk/identity-dev-env-auth#azure-cli-credential) - value must be set to `cli`
4. [The Default Azure Credential Chain](https://docs.microsoft.com/en-us/azure/developer/java/sdk/identity-azure-hosted-auth#default-azure-credential) - value must be set to `chain`

   The Default Azure Credential Chain supports authentication through environment variables, managed identities, IDE-specific credentials and the Azure CLI in the given order.

Example:

- Configuring option 1 as a property in the configuration file (see [Step 2: Enabling Carbon Secure Vault](#step-2-enabling-carbon-secure-vault)):

    - Legacy:
       ```
       secretRepositories.vault.properties.credential=env
       ```

    - Novel:
       ```
       secretProviders.vault.repositories.azure.properties.credential=env
       ```

- Alternatively, you could set it as an environment variable named `CREDENTIAL`:

   ```
   CREDENTIAL=env
   ```

Optional: If you choose to authenticate via a user-assigned managed identity, the managed identity's client id can be set in the same manner, i.e., as a configuration property or an environment variable named `MI_CLIENT_ID`.

If you are using the legacy configuration, you are required to proceed to [Step 5: Carbon Secure Vault Root Password](step-5-carbon-secure-vault-root-password-for-legacy-configuration-only).

However, if you are using the novel configurations, the next step isn't necessary and you're all set to use your Key Vault with the Identity Server's Carbon Secure Vault. Additionally, if you're interested in using your Key Vault with other secret repositories or need to troubleshoot any issues by debugging, see the sections on [Using an Azure Key Vault with Other Secret Repositories](using-an-azure-key-vault-with-other-secret-repositories) and [Debugging](debugging) respectively.

## Step 6: Carbon Secure Vault Root Password [For Legacy Configuration Only]
When you start the server, you will be required to provide the keystore and private key password, which is `wso2carbon` by default.

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
    1. Replace the values for the two properties `keystore.identity.store.secretProvider` and `keystore.identity.key.secretProvider` with `org.wso2.carbon.securevault.azure.handler.AzureSecretCallbackHandler`. This is the fully qualified class path of the Azure Key Vault Secret Callback Handler, which we will be using instead of the Default Secret Callback Handler.
    2. Provide the alias and version of your password(s) in the format `alias_version` as below. If only the alias is given, the latest version of the secret will be retrieved.
         ```
         keystore.identity.store.alias=<alias-and-version-of-password>
         keystore.identity.key.alias=<alias-and-version-of-password>
         ```
       If both the keystore and private key passwords are the same, only provide the keystore password (the first line). However, if they are not, provide the alias and version of the private key password as well.

Your configuration file would now be as follows.
```
keystore.identity.location=repository/resources/security/wso2carbon.jks
keystore.identity.type=JKS
keystore.identity.store.password=identity.store.password
keystore.identity.store.alias=<alias-and-version-of-password>
keystore.identity.store.secretProvider=org.wso2.carbon.securevault.azure.handler.AzureSecretCallbackHandler
keystore.identity.key.password=identity.key.password
keystore.identity.key.secretProvider=org.wso2.carbon.securevault.azure.handler.AzureSecretCallbackHandler
keystore.identity.key.alias=<alias-and-version-of-password>
carbon.secretProvider=org.wso2.securevault.secret.handler.SecretManagerSecretCallbackHandler
secVault.enabled=true
secretRepositories=vault
secretRepositories.vault.provider=org.wso2.carbon.securevault.azure.repository.AzureSecretRepositoryProvider
secretRepositories.vault.properties.keyVaultName=<name-of-the-azure-key-vault>
secretRepositories.vault.properties.credential=<choice-of-authentication-credential>
secretRepositories.vault.properties.managedIdentityClientId=<client-id-of-user-assigned-managed-identity>
```

That's it! Now you're ready to use your Key Vault as a secret repository with the Identity Server's Carbon Secure Vault. If you're interested in using your Key Vault with other secret repositories or need to troubleshoot any issues by debugging, see the sections on [Using an Azure Key Vault with Other Secret Repositories](using-an-azure-key-vault-with-other-secret-repositories) and [Debugging](debugging) respectively.

## Using an Azure Key Vault with Other Secret Repositories

The steps given above describe setting up an Azure Key Vault as your only secret repository. However, from Identity Server 5.12.0 onwards, the use of multiple secret repositories is supported as well. This means you can store and retrieve your Identity Server secrets from various places if you wish to, such as from an Azure Key Vault and AWS Secrets Manager.

The steps to set this up are as follows.

1. The novel configuration mentioned in [Step 2: Enabling Carbon Secure Vault](#step-2-enabling-carbon-secure-vault) need to be edited as given below with the relevant values being added as stated.

   ```
   carbon.secretProvider=org.wso2.securevault.secret.handler.SecretManagerSecretCallbackHandler
   secVault.enabled=true
   secretProviders=vault
   secretProviders.vault.provider=org.wso2.securevault.secret.repository.VaultSecretRepositoryProvider
   secretProviders.vault.repositories=azure,<other-repository-type>
   secretProviders.vault.repositories.azure=org.wso2.carbon.securevault.azure.repository.AzureSecretRepository
   secretProviders.vault.repositories.azure.properties.keyVaultName=<name-of-the-azure-key-vault>
   secretProviders.vault.repositories.azure.properties.credential=<choice-of-authentication-credential>
   secretProviders.vault.repositories.azure.properties.managedIdentityClientId=<client-id-of-user-assigned-managed-identity>
   secretProviders.vault.repositories.<other-repository-type>=<fully-qualified-classpath-of-the-other-repository>
   secretProviders.vault.repositories.<other-repository-type>.properties.<property-name>=<property-value>
   ```

2. In the `deployment.toml` file mentioned in [Step 3: Referencing Deployment Secrets](#step-3-referencing-deployment-secrets), the secret references should be in the format `$secret{provider:repository:alias}` or `$secret{provider:repository:alias_version}`. For example, your Key Vault secret references would be `$secret{vault:azure:superAdminPassword}`, while your other repository references would be `$secret{vault:<other-repository-type>:superAdminPassword}`.

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
