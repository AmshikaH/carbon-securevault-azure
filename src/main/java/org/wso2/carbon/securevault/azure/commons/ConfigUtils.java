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
 * Config Utils class to read the secret-conf.properties config file,
 * its properties and environment variables containing configurations.
 */
public class ConfigUtils {

    private static final String SECURITY = "security";
    private static final String ENV_PREFIX = "AKV" + DELIMITER;
    private static final String CONFIG_FILE_PATH = CarbonUtils.getCarbonConfigDirPath() +
            File.separator + SECURITY + File.separator + CONFIG_FILE;
    private static final Log log = LogFactory.getLog(ConfigUtils.class);
    private static Properties properties;
    private static String propertyPrefix;

    private static ConfigUtils instance;

    public static synchronized ConfigUtils getInstance() {

        if (instance == null) {
            instance = new ConfigUtils();
        }
        return instance;
    }

    /**
     * Reads configuration properties from the config file.
     *
     * @return Configuration properties from file.
     */
    @SuppressFBWarnings("PATH_TRAVERSAL_IN")
    public static synchronized Properties getConfigProperties() {

        if (properties == null) {
            InputStream inputStream = null;
            properties = new Properties();
            try {
                inputStream = new FileInputStream(CONFIG_FILE_PATH);
                properties.load(inputStream);
            } catch (IOException e) {
                log.error("Error while loading configurations from configuration file'" + CONFIG_FILE + "'.", e);
            } finally {
                try {
                    if (inputStream != null) {
                        inputStream.close();
                    }
                } catch (IOException e) {
                    log.warn("Error closing input stream of configuration file.");
                }
            }
        }

        return properties;
    }

    /**
     * Reads configuration from the "secret-conf.properties" config file. If a value is not found in the file,
     * reads from environment variables. If the configuration has not been specified in either of the locations,
     * the default value is used.
     *
     * @param properties Configuration properties from file.
     * @param configName The name of the configuration property.
     * @param defaultValue The default value of the configuration property.
     * @return The value of the configuration property.
     */
    public String getConfig(Properties properties, String configName, String defaultValue) { //TODO

        String configValue = properties.getProperty(readConfigPrefixType(properties) + configName);

        if (StringUtils.isNotEmpty(configValue)) {
            if (log.isDebugEnabled()) {
                log.debug("Using " + configName.replaceAll(REGEX, "") + " found in config file.");
            }
        } else {
            configValue = getEnvOrDefaultConfig(configValue, configName, defaultValue);
        }

        if (StringUtils.isNotEmpty(configValue)) {
            configValue = configValue.trim();
        }

        return configValue;
    }

    private String getEnvOrDefaultConfig(String value, String configName, String defaultValue) {

        if (StringUtils.isEmpty(value)) {
            value = System.getenv(ENV_PREFIX + configName);
            if (StringUtils.isNotEmpty(value)) {
                if (log.isDebugEnabled()) {
                    log.debug("Using " + configName.replaceAll(REGEX, "") + " found as an environment variable.");
                }
            } else {
                value = defaultValue;
                if (log.isDebugEnabled()) {
                    log.debug(configName.replaceAll(REGEX, "") + " not configured. Using default value: " +
                            value.replaceAll(REGEX, "") + ".");
                }
            }
        }

        return value;
    }
    /**
     *
     * Reads whether the configuration used is the legacy or novel one and sets the prefix accordingly.
     *
     * @param properties Configuration properties from file.
     * @return The property prefix used in the config file.
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
