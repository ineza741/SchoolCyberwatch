package com.schoolcyberwatch.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 * Wazuh Indexer (OpenSearch) settings. In Wazuh 4.x alerts are NOT served by
 * the manager API - they live in the wazuh-alerts-* indices on the indexer
 * (port 9200). Values come from application.properties, which reads
 * environment variables (WAZUH_INDEXER_URL, WAZUH_INDEXER_USERNAME,
 * WAZUH_INDEXER_PASSWORD, WAZUH_INDEXER_TIMEOUT). Credentials never leave
 * the backend.
 */
@Component
@ConfigurationProperties(prefix = "wazuh.indexer")
public class WazuhIndexerProperties {

    /** e.g. https://192.168.56.101:9200 */
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
