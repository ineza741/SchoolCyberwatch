package com.schoolcyberwatch.service;

import com.schoolcyberwatch.config.WazuhProperties;
import com.schoolcyberwatch.dto.EndpointInfo;
import com.schoolcyberwatch.dto.SecurityEvent;
import org.springframework.context.annotation.Lazy;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import com.fasterxml.jackson.databind.JsonNode;

import java.util.ArrayList;
import java.util.List;

/**
 * High-level Wazuh integration for School CyberWatch.
 *
 * Architecture: React -> Spring Boot (this service) -> Wazuh.
 * Credentials stay in the backend; the frontend only ever sees the
 * simplified SecurityEvent/EndpointInfo objects.
 *
 * Data sources (Wazuh 4.x):
 *   - Alerts:  Wazuh Indexer (OpenSearch, port 9200), wazuh-alerts-* indices.
 *              The manager API does not serve alert data.
 *   - Agents:  Wazuh Manager API (port 55000).
 *
 * Monitored rules:
 *   60122 failed login, 100200 brute force, 550 file modified, 553 file deleted.
 */
@Service
public class WazuhService {

    /** Comma-separated rule filter applied to indexer alert queries. */
    private static final String RULE_FILTER = "60122,100200,550,553";
    private static final int MAX_ALERTS = 200;

    private final WazuhIndexerClient indexerClient;
    private final WazuhClient client;
    private final WazuhProperties properties;
    private final SecurityEventMapper mapper;
    private final NotificationService notificationService;

    public WazuhService(WazuhIndexerClient indexerClient, WazuhClient client,
                        WazuhProperties properties, SecurityEventMapper mapper,
                        @Lazy NotificationService notificationService) {
        this.indexerClient = indexerClient;
        this.client = client;
        this.properties = properties;
        this.mapper = mapper;
        this.notificationService = notificationService;
    }

    /**
     * True when alert data can be fetched, i.e. the indexer is reachable and
     * credentials work. (Alerts are the data this dashboard exists for.)
     */
    public boolean isAvailable() {
        return indexerClient.isAvailable();
    }

    /**
     * Fetches recent security events from the Wazuh indexer, filtered to the
     * four monitored rules, newest first. Throws WazuhUnavailableException
     * when the indexer cannot be reached (handled by GlobalExceptionHandler).
     */
    public List<SecurityEvent> getRecentAlerts(int limit) {
        int capped = Math.min(Math.max(limit, 1), MAX_ALERTS);
        List<JsonNode> alerts = indexerClient.searchAlerts(RULE_FILTER, null, capped);

        List<SecurityEvent> events = new ArrayList<>();
        for (JsonNode alert : alerts) {
            SecurityEvent event = mapper.fromWazuhAlert(alert);
            if (event != null) {
                events.add(event);
                // High/critical events (brute force) trigger a deduplicated email.
                if (notificationService.shouldNotify(event)) {
                    notificationService.sendCriticalAlertEmail(event);
                }
            }
        }
        return events;
    }

    /** Monitored computers (Wazuh agents) - still served by the manager API. */
    public List<EndpointInfo> getAgents() {
        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("sort", "name");

        JsonNode data = client.getData("/agents", params);
        List<EndpointInfo> endpoints = new ArrayList<>();
        JsonNode affectedItems = data.path("affected_items");
        if (affectedItems.isArray()) {
            for (JsonNode agent : affectedItems) {
                String status = agent.path("status").asText("unknown");
                // Wazuh's manager itself appears as agent 000 - hide it.
                if ("000".equals(agent.path("id").asText())) {
                    continue;
                }
                String osName = agent.path("os").path("name").asText("");
                String osVersion = agent.path("os").path("version").asText("");
                String os = (osName + " " + osVersion).trim();
                if (os.isEmpty()) {
                    os = "Unknown OS";
                }
                endpoints.add(new EndpointInfo(
                        agent.path("id").asText(),
                        agent.path("name").asText("Unknown"),
                        agent.path("ip").asText(""),
                        os,
                        "active".equalsIgnoreCase(status) ? "Online" : "Offline",
                        agent.path("last_keepalive").asText(""),
                        agent.path("version").asText("")));
            }
        }
        return endpoints;
    }

    /**
     * Counts alerts for the given rule since the given instant.
     * Used by the dashboard summary and PDF reports.
     */
    public long countAlerts(String ruleId, String sinceIso) {
        return indexerClient.countAlerts(ruleId, sinceIso);
    }

    /** Counts agents (excluding the manager itself, agent 000). */
    public long countAgents() {
        JsonNode data = client.getData("/agents", null);
        long total = data.path("total_affected_items").asLong(0);
        return Math.max(total - 1, 0);
    }
}
