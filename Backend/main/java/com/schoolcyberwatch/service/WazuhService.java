package com.schoolcyberwatch.service;

import com.schoolcyberwatch.config.WazuhProperties;
import com.schoolcyberwatch.dto.EndpointInfo;
import com.schoolcyberwatch.dto.SecurityEvent;
import org.springframework.context.annotation.Lazy;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import com.fasterxml.jackson.databind.JsonNode;

import java.time.Duration;
import java.time.Instant;
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
 *   60122 failed login, 100200 brute force, 550 file modified, 553 file deleted,
 *   62123 malware detected, 100300 inbound network connection,
 *   100301 possible network scan.
 */
@Service
public class WazuhService {

    /**
     * Comma-separated rule filter applied to indexer alert queries.
     * 62124 (Defender remediation) is intentionally excluded - the threat
     * (62123) and its cleanup must not count as two malware events.
     */
    public static final String RULE_FILTER = "60122,100200,550,553,62123,100300,100301";
    private static final int MAX_ALERTS = 500;

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

    /** Filter criteria for /api/alerts, applied indexer-side where possible. */
    public record AlertFilter(String type, String severity, String ruleId, String agentId,
                              String fromIso, String toIso, String search, int limit) {
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
     * monitored rules, newest first. Throws WazuhUnavailableException
     * when the indexer cannot be reached (handled by GlobalExceptionHandler).
     */
    public List<SecurityEvent> getRecentAlerts(int limit) {
        return getAlerts(new AlertFilter(null, null, null, null, null, null, null, limit));
    }

    /**
     * Fetches security events with the given filter applied inside the
     * Wazuh indexer (type/severity/rule/agent/date), so large datasets are
     * not dragged across the network just to be dropped.
     */
    public List<SecurityEvent> getAlerts(AlertFilter filter) {
        int capped = Math.min(Math.max(filter.limit(), 1), MAX_ALERTS);

        List<String> rules = rulesForFilter(filter.type(), filter.ruleId());
        List<JsonNode> alerts = indexerClient.searchAlerts(
                rules == null ? RULE_FILTER : String.join(",", rules),
                filter.fromIso(), filter.toIso(), filter.agentId(), capped + 50);

        List<SecurityEvent> events = new ArrayList<>();
        for (JsonNode alert : alerts) {
            SecurityEvent event = mapper.fromWazuhAlert(alert);
            if (event == null) {
                continue;
            }
            // Severity is derived from the rule level - filter locally.
            if (filter.severity() != null && !filter.severity().isBlank()
                    && !event.getSeverity().equalsIgnoreCase(filter.severity().trim())) {
                continue;
            }
            // Free-text search across computer/title/description/rule.
            if (filter.search() != null && !filter.search().isBlank()) {
                if (!matchesSearch(event, filter.search().trim())) {
                    continue;
                }
            }
            events.add(event);
            // High/critical events (brute force, malware, scans) trigger a
            // deduplicated email.
            if (notificationService.shouldNotify(event)) {
                notificationService.sendCriticalAlertEmail(event);
            }
            if (events.size() >= capped) {
                break;
            }
        }
        return events;
    }

    /** One alert by its Wazuh alert id, or null when it does not exist. */
    public SecurityEvent getAlertById(String id) {
        JsonNode alert = indexerClient.fetchAlertById(id);
        return alert == null ? null : mapper.fromWazuhAlert(alert);
    }

    /**
     * Counts alerts for the given rule since the given instant.
     * Used by the dashboard summary and PDF reports.
     */
    public long countAlerts(String ruleId, String sinceIso) {
        return indexerClient.countAlerts(ruleId, sinceIso);
    }

    /** Counts monitored-rule alerts grouped by rule id (dashboard statistics). */
    public java.util.Map<String, Long> countAlertsByRule(String sinceIso, String untilIso) {
        return indexerClient.countAlertsByRule(RULE_FILTER, sinceIso, untilIso);
    }

    /** Counts monitored-rule alerts grouped by Wazuh rule level. */
    public java.util.Map<String, Long> countAlertsByLevel(String sinceIso, String untilIso) {
        return indexerClient.countAlertsByLevel(RULE_FILTER, sinceIso, untilIso);
    }

    /** Counts monitored-rule alerts grouped by local calendar day. */
    public java.util.Map<String, Long> countAlertsByDay(String sinceIso, String untilIso) {
        return indexerClient.countAlertsByDay(RULE_FILTER, sinceIso, untilIso);
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

    /** Counts agents (excluding the manager itself, agent 000). */
    public long countAgents() {
        JsonNode data = client.getData("/agents", null);
        long total = data.path("total_affected_items").asLong(0);
        return Math.max(total - 1, 0);
    }

    // ------------------------------------------------------------------
    // filter helpers
    // ------------------------------------------------------------------

    /**
     * Resolves the rule-id list for a type/ruleId filter. Null means "use the
     * default RULE_FILTER". Type values map to the rules they can come from;
     * unknown types yield an empty list (no results, not everything).
     */
    private static List<String> rulesForFilter(String type, String ruleId) {
        if (ruleId != null && !ruleId.isBlank()) {
            return List.of(ruleId.trim());
        }
        if (type == null || type.isBlank()) {
            return null;
        }
        switch (type.trim().toUpperCase()) {
            case "FAILED_LOGIN":
                return List.of("60122");
            case "BRUTE_FORCE":
                return List.of("100200");
            case "FILE_MODIFIED":
                return List.of("550");
            case "FILE_DELETED":
                return List.of("553");
            case "MALWARE_DETECTED":
                return List.of("62123");
            case "NETWORK_CONNECTION":
                return List.of("100300");
            case "NETWORK_SCAN":
                return List.of("100301");
            default:
                return List.of();
        }
    }

    private static boolean matchesSearch(SecurityEvent event, String needle) {
        String n = needle.toLowerCase();
        return contains(event.getComputer(), n)
                || contains(event.getTitle(), n)
                || contains(event.getDescription(), n)
                || contains(event.getRuleId(), n)
                || contains(event.getUsername(), n)
                || contains(event.getFilePath(), n)
                || contains(event.getSourceIp(), n);
    }

    private static boolean contains(String value, String needle) {
        return value != null && value.toLowerCase().contains(needle);
    }
}
