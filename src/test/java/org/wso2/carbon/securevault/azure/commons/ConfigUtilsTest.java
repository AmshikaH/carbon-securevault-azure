package org.wso2.carbon.securevault.azure.commons;

import org.apache.commons.logging.Log;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.internal.util.reflection.FieldSetter;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.Properties;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Test class for ConfigUtils.
 */
public class ConfigUtilsTest {

    private static ConfigUtils configUtils = ConfigUtils.getInstance();

    @Mock
    private static Log log = mock(Log.class);

    @BeforeAll
    public static void setUp() throws NoSuchFieldException, IllegalAccessException {

        // Prevent logging to keep console clean:
        Mockito.doNothing().when(log).info(anyString());
        Mockito.doNothing().when(log).error(anyString());
        Mockito.doNothing().when(log).error(anyString(), any(Throwable.class));
        when(log.isDebugEnabled()).thenReturn(false);
        Field field = ConfigUtils.class.getDeclaredField("log");
        field.setAccessible(true);
        Field modifiersField = Field.class.getDeclaredField("modifiers");
        modifiersField.setAccessible(true);
        modifiersField.setInt(field, field.getModifiers() & ~Modifier.FINAL);
        FieldSetter.setField(configUtils, field, log);
    }

    @Test
    public void givenConfigInFileProperties_getAzureSecretRepositoryConfig_thenReturnConfigValue() {

        Properties propertiesInFile = new Properties();
        propertiesInFile.put("secretProviders.vault.repositories.azure.properties.credential", "env");
        String actualConfigValue = configUtils.getAzureSecretRepositoryConfig(propertiesInFile,
                "credential");
        String expectedConfigValue = "env";
        assertEquals(expectedConfigValue, actualConfigValue);
    }

    @Test
    public void givenConfigInEnvironmentVariables_getAzureSecretRepositoryConfig_thenReturnConfigValue() {

        Properties propertiesInFile = new Properties();
        String actualConfigValue = configUtils.getAzureSecretRepositoryConfig(propertiesInFile,
                "keyVaultName");
        String expectedConfigValue = "kv-test";
        assertEquals(expectedConfigValue, actualConfigValue);
    }

    @Test
    public void givenConfigNotProvided_getAzureSecretRepositoryConfig_thenReturnNull() {

        Properties propertiesInFile = new Properties();
        String actualConfigValue = configUtils.getAzureSecretRepositoryConfig(propertiesInFile,
                "propertyName");
        assertNull(actualConfigValue);
    }
}
