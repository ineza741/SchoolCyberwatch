package com.schoolcyberwatch.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 * Wazuh Manager API settings. Values come from application.properties,
 * which reads environment variables (WAZUH_API_URL, WAZUH_API_USERNAME,
 * WAZUH_API_PASSWORD, WAZUH_API_TIMEOUT). Credentials never leave the backend.
 */
@Component
@ConfigurationProperties(prefix = "wazuh.api")
public class WazuhProperties {

    /** e.g. https://192.168.56.101:55000 */
    private String baseUrl;

    private String username;

    private String password;

    /** Connect/read timeout in seconds. */
    private int timeoutSeconds = 8;

    public String getBaseUrl() {
        return baseUrl;
    }

    public void setBaseUrl(String baseUrl) {
        this.baseUrl = baseUrl;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public int getTimeoutSeconds() {
        return timeoutSeconds;
    }

    public void setTimeoutSeconds(int timeoutSeconds) {
        this.timeoutSeconds = timeoutSeconds;
    }
}
