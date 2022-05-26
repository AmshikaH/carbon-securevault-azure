/*
 * Copyright (c) 2022, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wso2.carbon.securevault.azure.commons;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.securevault.azure.exception.AzureSecretRepositoryException;
import org.wso2.carbon.utils.CarbonUtils;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

import static org.wso2.carbon.securevault.azure.commons.Constants.CONFIG_FILE;
import static org.wso2.carbon.securevault.azure.commons.Constants.DELIMITER;
import static org.wso2.carbon.securevault.azure.commons.Constants.LEGACY_CONFIG_PREFIX;
import static org.wso2.carbon.securevault.azure.commons.Constants.NOVEL_CONFIG_PREFIX;
import static org.wso2.carbon.securevault.azure.commons.Constants.REGEX;
import static org.wso2.carbon.securevault.azure.commons.Constants.SECRET_REPOSITORIES;

/**
 * Config Utils class to read the secret-conf.properties file and
 * its properties as well as environment variables containing configurations.
 */
public class ConfigUtils {

    private static final String SECURITY = "security";
    private static final String ENV_PREFIX = "AKV";
    private static final String CONFIG_FILE_PATH = CarbonUtils.getCarbonConfigDirPath() +
            File.separator + SECURITY + File.separator + CONFIG_FILE;
    private static final Log log = LogFactory.getLog(ConfigUtils.class);
    private static Properties properties;
    private static String propertyPrefix;
    private static ConfigUtils instance;

    /**
     * Gets the instance of the ConfigUtils class.
     *
     * @return Instance of ConfigUtils.
     */
    public static synchronized ConfigUtils getInstance() {

        if (instance == null) {
            instance = new ConfigUtils();
        }
        return instance;
    }

    /**
     * Reads configuration properties from the secret-conf.properties file.
     *
     * @return Configuration properties from the secret-conf.properties file.
     * @throws AzureSecretRepositoryException If an error occurs while reading the secret-conf.properties file.
     */
    @SuppressFBWarnings("PATH_TRAVERSAL_IN")
    public static synchronized Properties getConfigProperties() throws AzureSecretRepositoryException {

        if (properties == null) {
            properties = new Properties();
            try (InputStream inputStream = new FileInputStream(CONFIG_FILE_PATH)) {
                properties.load(inputStream);
            } catch (IOException e) {
                throw new AzureSecretRepositoryException("Error while loading configurations from "
                        + CONFIG_FILE + " file.", e);
            }
        }
        return properties;
    }

    /**
     * Gets a configuration; first, it is attempted to read the value from the secret-config.properties file.
     * If a value is not found in the file, it is attempted to read the value from environment variables.
     * If a value is not found here either, the default value is returned.
     *
     * @param properties   Configuration properties from the secret-conf.properties file.
     * @param configName   The name of the configuration property.
     * @param defaultValue The default value of the configuration property.
     * @return The value of the configuration property.
     */
    public String getConfig(Properties properties, String configName, String defaultValue) {

        String configValue = properties.getProperty(readConfigPrefixType(properties) + configName);
        if (StringUtils.isNotEmpty(configValue)) {
            if (log.isDebugEnabled()) {
                log.debug("Using " + configName.replaceAll(REGEX, "") + " found in config file.");
            }
        } else {
            configValue = getEnvOrDefaultConfig(configName, defaultValue);
        }
        if (StringUtils.isNotEmpty(configValue)) {
            configValue = configValue.trim();
        }
        return configValue;
    }

    /**
     * Reads a configuration property from environment variables. If a value is not found,
     * the default value is returned.
     *
     * @param configName   The name of the configuration property.
     * @param defaultValue The default value of the configuration property.
     * @return The value of the configuration property.
     */
    private String getEnvOrDefaultConfig(String configName, String defaultValue) {

        String configValue = System.getenv(ENV_PREFIX + DELIMITER + configName);
        if (StringUtils.isNotEmpty(configValue)) {
            if (log.isDebugEnabled()) {
                log.debug("Using " + configName.replaceAll(REGEX, "") + " found as an environment variable.");
            }
            return configValue;
        }
        configValue = defaultValue;
        if (log.isDebugEnabled()) {
            log.debug(configName.replaceAll(REGEX, "") + " not configured. Using default value: " +
                    configValue.replaceAll(REGEX, "") + ".");
        }
        return configValue;
    }

    /**
     * Reads whether the configuration used is of the legacy or novel type and sets the prefix accordingly.
     *
     * @param properties Configuration properties from the secret-conf.properties file.
     * @return The property prefix used in the secret-conf.properties file.
     */
    private static String readConfigPrefixType(Properties properties) {

        if (StringUtils.isEmpty(propertyPrefix)) {
            String legacyProvidersString = properties.getProperty(SECRET_REPOSITORIES, null);
            if (StringUtils.isEmpty(legacyProvidersString)) {
                if (log.isDebugEnabled()) {
                    log.debug("Legacy provider not found. Using novel configurations.");
                }
                propertyPrefix = NOVEL_CONFIG_PREFIX;
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Legacy provider found. Using legacy configurations.");
                }
                propertyPrefix = LEGACY_CONFIG_PREFIX;
            }
        }
        return propertyPrefix;
    }
}
