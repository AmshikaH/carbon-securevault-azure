package org.wso2.carbon.securevault.azure.repository;

import com.azure.core.exception.ResourceNotFoundException;
import com.azure.security.keyvault.secrets.SecretClient;
import com.azure.security.keyvault.secrets.models.KeyVaultSecret;
import org.apache.commons.logging.Log;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.internal.util.reflection.FieldSetter;
import org.wso2.securevault.DecryptionProvider;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Test class for AzureSecretRepository.
 */
public class AzureSecretRepositoryTest {

    private static AzureSecretRepository azureSecretRepository = new AzureSecretRepository();

    @Mock
    private static SecretClient secretClient = mock(SecretClient.class);

    @Mock
    private static DecryptionProvider baseCipher = mock(DecryptionProvider.class);

    @Mock
    private static Log log = mock(Log.class);

    @BeforeAll
    public static void setUp() throws NoSuchFieldException, IllegalAccessException {

        // Prevent logging to keep console clean:
        Mockito.doNothing().when(log).info(anyString());
        Mockito.doNothing().when(log).error(anyString());
        Mockito.doNothing().when(log).error(anyString(), any(Throwable.class));
        when(log.isDebugEnabled()).thenReturn(false);
        Field field = AzureSecretRepository.class.getDeclaredField("log");
        field.setAccessible(true);
        Field modifiersField = Field.class.getDeclaredField("modifiers");
        modifiersField.setAccessible(true);
        modifiersField.setInt(field, field.getModifiers() & ~Modifier.FINAL);
        FieldSetter.setField(azureSecretRepository, field, log);

        // Version 12345 of secret named "KEYSTORE-PASSWORD"
        KeyVaultSecret keyVaultSecret1 = mock(KeyVaultSecret.class);
        when(secretClient.getSecret("KEYSTORE-PASSWORD", "12345")).thenReturn(keyVaultSecret1);
        when(keyVaultSecret1.getValue()).thenReturn("wso2@123");

        // Latest version of secret named "KEYSTORE-PASSWORD"
        KeyVaultSecret keyVaultSecret2 = mock(KeyVaultSecret.class);
        when(secretClient.getSecret("KEYSTORE-PASSWORD", null)).thenReturn(keyVaultSecret2);
        when(secretClient.getSecret("KEYSTORE-PASSWORD", "")).thenReturn(keyVaultSecret2);
        when(keyVaultSecret2.getValue()).thenReturn("wso2@456");

        // Latest version of secret named "ADMIN-PASSWORD" in decrypted form
        KeyVaultSecret keyVaultSecret3 = mock(KeyVaultSecret.class);
        when(secretClient.getSecret("ADMIN-PASSWORD", null)).thenReturn(keyVaultSecret3);
        when(keyVaultSecret3.getValue()).thenReturn("encryptedValueOfSecret");
        byte[] byteArrayOfEncryptedSecret = {101, 110, 99, 114, 121, 112, 116, 101, 100, 86, 97, 108, 117, 101, 79, 102,
                83, 101, 99, 114, 101, 116};
        byte[] byteArrayOfDecryptedSecret = {100, 101, 99, 114, 121, 112, 116, 101, 100, 86, 97, 108, 117, 101, 79, 102,
                83, 101, 99, 114, 101, 116};
        when(baseCipher.decrypt(byteArrayOfEncryptedSecret)).thenReturn(byteArrayOfDecryptedSecret);

        // Secret not found in Key Vault
        when(secretClient.getSecret("KEYSSTORE-PASSWORD", null)).thenThrow(new
                ResourceNotFoundException("Secret not found.", null));
    }

    @Test
    public void givenSecretNameOnly_whenGetSecret_returnLatestVersionOfSecret() {

        String actualSecretValue = azureSecretRepository.getSecret("KEYSTORE-PASSWORD");
        String expectedStringValue = "wso2@456";
        assertEquals(expectedStringValue, actualSecretValue);
    }

    @Test
    public void givenSecretNameAndVersion_whenGetSecret_returnSpecifiedVersionOfSecret() {

        String actualSecretValue = azureSecretRepository.getSecret("KEYSTORE-PASSWORD#12345");
        String expectedSecretValue = "wso2@123";
        assertEquals(expectedSecretValue, actualSecretValue);
    }

    @Test
    public void givenSecretNameNotInKeyVault_whenGetSecret_returnEmptySecret() {

        String actualSecretValue = azureSecretRepository.getSecret("KEYSSTORE-PASSWORD");
        String expectedSecretValue = "";
        assertEquals(expectedSecretValue, actualSecretValue);
    }

    @Test
    public void givenSecretNameWithHashtagButNoVersion_whenGetSecret_returnLatestVersionOfSecret() {

        String actualSecretValue = azureSecretRepository.getSecret("KEYSTORE-PASSWORD#");
        String expectedSecretValue = "wso2@456";
        assertEquals(expectedSecretValue, actualSecretValue);
    }

    @Test
    public void givenSecretNameNotMatchingAcceptedRegex_whenGetSecret_returnEmptySecret() {

        String actualSecretValue = azureSecretRepository.getSecret("KEYSTORE-PASSWORD_");
        String expectedSecretValue = "";
        assertEquals(expectedSecretValue, actualSecretValue);
    }

    @Test
    public void givenEmptyAlias_whenGetSecret_returnEmptySecret() {

        String actualSecretValue = azureSecretRepository.getSecret("");
        String expectedSecretValue = "";
        assertEquals(expectedSecretValue, actualSecretValue);
    }

    @Test
    public void givenEmptySecretNameWithVersion_whenGetSecret_returnEmptySecret() {

        String actualSecretValue = azureSecretRepository.getSecret("#12345");
        String expectedSecretValue = "";
        assertEquals(expectedSecretValue, actualSecretValue);
    }

    @Test
    public void givenVersionDelimiterOnlyWithNoSecretNameOrVersion_whenGetSecret_returnEmptySecret() {

        String actualSecretValue = azureSecretRepository.getSecret("#");
        String expectedSecretValue = "";
        assertEquals(expectedSecretValue, actualSecretValue);
    }

    @Test
    public void givenEncryptedSecretNameWithEncryptionEnabled_whenGetSecret_returnDecryptedValueOfSecret() {

        try {
            FieldSetter.setField(azureSecretRepository, azureSecretRepository.getClass().getDeclaredField(
                    "encryptionEnabled"), true);
            FieldSetter.setField(azureSecretRepository, azureSecretRepository.getClass().getDeclaredField(
                    "baseCipher"), baseCipher);
            String actualSecretValue = azureSecretRepository.getSecret("ADMIN-PASSWORD");
            String expectedSecretValue = "decryptedValueOfSecret";
            assertEquals(expectedSecretValue, actualSecretValue);
        } catch (NoSuchFieldException e) {
            // do nothing
        } finally {
            try {
                FieldSetter.setField(azureSecretRepository, azureSecretRepository.getClass().getDeclaredField(
                        "encryptionEnabled"), false);
                FieldSetter.setField(azureSecretRepository, azureSecretRepository.getClass().getDeclaredField(
                        "baseCipher"), null);
            } catch (NoSuchFieldException e) {
                // do nothing
            }
        }
    }

    @Test
    public void givenNullSecretClient_whenGetSecret_returnEmptySecret() {

        try {
            FieldSetter.setField(azureSecretRepository, azureSecretRepository.getClass().getDeclaredField(
                    "secretClient"), null);
            String actualSecretValue = azureSecretRepository.getSecret("KEYSTORE-PASSWORD");
            String expectedSecretValue = "";
            assertEquals(expectedSecretValue, actualSecretValue);
        } catch (NoSuchFieldException e) {
            // do nothing
        } finally {
            try {
                FieldSetter.setField(azureSecretRepository, azureSecretRepository.getClass().getDeclaredField(
                        "secretClient"), secretClient);
            } catch (NoSuchFieldException e) {
                // do nothing
            }
        }
    }

    @Test
    public void givenEncryptedSecretNameWithEncryptionEnabled_whenGetEncryptedData_returnEncryptedValueOfSecret() {

        try {
            FieldSetter.setField(azureSecretRepository, azureSecretRepository.getClass().getDeclaredField(
                    "encryptionEnabled"), true);
            String actualSecretValue = azureSecretRepository.getEncryptedData("ADMIN-PASSWORD");
            String expectedSecretValue = "encryptedValueOfSecret";
            assertEquals(expectedSecretValue, actualSecretValue);
        } catch (NoSuchFieldException e) {
            // do nothing
        } finally {
            try {
                FieldSetter.setField(azureSecretRepository, azureSecretRepository.getClass().getDeclaredField(
                        "encryptionEnabled"), false);
            } catch (NoSuchFieldException e) {
                // do nothing
            }
        }
    }

    @Test
    public void givenEncryptedSecretNameWithEncryptionDisabled_whenGetEncryptedData_returnEncryptedValueOfSecret() {

        assertThrows(UnsupportedOperationException.class, () -> azureSecretRepository.getEncryptedData(
                "ADMIN-PASSWORD"));
    }
}
