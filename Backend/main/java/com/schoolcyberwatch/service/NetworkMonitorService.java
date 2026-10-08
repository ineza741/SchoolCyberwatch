package com.schoolcyberwatch.service;

import com.schoolcyberwatch.dto.NetworkEvent;
import com.schoolcyberwatch.dto.SecurityEvent;
import com.fasterxml.jackson.databind.JsonNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Network Monitoring capability (the sixth detection category).
 *
 * Reads network-related security events that already flow through the
 * existing Wazuh environment - no new agent, IDS or engine:
 *   - Rule 100300: inbound permitted network connection (Windows Event 5156)
 *     - normal traffic, never presented as an attack
 *   - Rule 100301: possible network scan (correlated inbound connections)
 *   - SSH activity on the Wazuh manager VM (rules 5710/5715/5716/5718/5720/576x)
 *   - Windows network logon events on monitored endpoints (60122/100200/60118
 *     with a remote peer address in win.eventdata.ipAddress)
 *
 * Fields the Wazuh event does not provide (destination IP, protocol on many
 * events, ports) are returned as "N/A" - never fabricated.
 */
@Service
public class NetworkMonitorService {

    private static final Logger log = LoggerFactory.getLogger(NetworkMonitorService.class);

    /**
     * Wazuh rules that carry network context (source IP / ports) in this
     * deployment. Verified against real events in the wazuh-alerts-* indices.
     */
    private static final Set<String> NETWORK_RULE_IDS = Set.of(
            "5710", "5715", "5716", "5718", "5720", "5760", "5762", "5763",
            "60122", "100200", "60118", "100300", "100301");

    private static final String LOOPBACK = "127.0.0.1";
    private static final String SCHOOL_NETWORK_RULES = "100300,100301";
    /** Human-friendly titles for the network rules (reuses existing naming). */
    private static final java.util.Map<String, String> NETWORK_TITLES = java.util.Map.ofEntries(
            java.util.Map.entry("5710", "SSH authentication failure"),
            java.util.Map.entry("5715", "SSH login succeeded"),
            java.util.Map.entry("5716", "SSH authentication failure (public key)"),
            java.util.Map.entry("5718", "SSH session opened"),
            java.util.Map.entry("5720", "SSH multiple authentication failures"),
            java.util.Map.entry("5760", "SSH brute-force attempt"),
            java.util.Map.entry("5762", "SSH brute-force attempt"),
            java.util.Map.entry("5763", "SSH brute force (sshd)"),
            java.util.Map.entry("60122", "Failed network logon"),
            java.util.Map.entry("100200", "Possible brute-force attack (network)"),
            java.util.Map.entry("60118", "Successful network logon"),
            java.util.Map.entry("100300", "Inbound network connection"),
            java.util.Map.entry("100301", "Possible network scan"));

    private final WazuhIndexerClient indexerClient;
    private final NotificationService notificationService;
    private final int windowHours;

    public NetworkMonitorService(WazuhIndexerClient indexerClient,
                                 NotificationService notificationService,
                                 @Value("${app.network.window-hours:72}") int windowHours) {
        this.indexerClient = indexerClient;
        this.notificationService = notificationService;
        this.windowHours = windowHours;
    }

    /** Small stats bundle for the Network Monitoring summary cards and PDF report. */
    public record NetworkSummary(long totalEvents, long highSeverity, long affectedEndpoints) {
    }

    /**
     * Returns recent network events, newest first. Pure-loopback logons
     * (source 127.0.0.1 with no remote address) are local activity, not
     * network activity, and already appear on the Security Alerts page.
     */
    public List<NetworkEvent> getRecentEvents(int limit) {
        String ruleCsv = String.join(",", NETWORK_RULE_IDS);
        String sinceIso = Instant.now().minus(Duration.ofHours(windowHours)).toString();
        // Fetch a full page first, then filter: most alerts in the window are
        // local activity, so applying the limit before filtering would return
        // too few (or zero) real network events.
        List<JsonNode> alerts = indexerClient.searchAlerts(ruleCsv, sinceIso, 1000);

        List<NetworkEvent> events = new ArrayList<>();
        int wanted = Math.max(Math.min(limit, 1000), 1);
        for (JsonNode alert : alerts) {
            NetworkEvent event = toNetworkEvent(alert);
            if (event != null) {
                events.add(event);
                if (events.size() >= wanted) {
                    break;
                }
            }
        }
        return events;
    }

    /** Counts for the Network Monitoring page cards and the PDF report. */
    public NetworkSummary getSummary() {
        List<NetworkEvent> events = getRecentEvents(1000);
        long high = events.stream()
                .map(NetworkEvent::getSeverity)
                .filter(s -> "High".equalsIgnoreCase(s) || "Critical".equalsIgnoreCase(s))
                .count();
        Set<String> computers = new HashSet<>();
        events.forEach(e -> computers.add(e.getComputer()));
        return new NetworkSummary(events.size(), high, computers.size());
    }

    /** Exact dashboard count for the two School CyberWatch network rules. */
    public long countSchoolNetworkAlerts() {
        Instant until = Instant.now();
        String sinceIso = until.minus(Duration.ofHours(windowHours)).toString();
        return indexerClient.countAlerts(SCHOOL_NETWORK_RULES, sinceIso, until.toString(), null);
    }

    /**
     * High/critical network alerts (brute force 100200, sshd 5760/5762/5720)
     * as SecurityEvents, for the existing email pipeline with its dedup.
     */
    public List<SecurityEvent> getHighSeverityForNotifications() {
        return getRecentEvents(500).stream()
                .filter(e -> "High".equalsIgnoreCase(e.getSeverity())
                        || "Critical".equalsIgnoreCase(e.getSeverity()))
                .map(NetworkEvent::toSecurityEvent)
                .toList();
    }

    /**
     * Converts one Wazuh alert (_source JSON) to a NetworkEvent, or null when
     * it is not network-related (wrong rule, loopback-only, no source IP).
     */
    private NetworkEvent toNetworkEvent(JsonNode alert) {
        JsonNode rule = alert.path("rule");
        String ruleId = rule.path("id").asText("");
        if (!NETWORK_RULE_IDS.contains(ruleId)) {
            return null;
        }

        String srcIp = blankToNull(firstNonBlank(
                alert.path("data").path("srcip").asText(null),
                alert.path("data").path("win").path("eventdata").path("sourceAddress").asText(null)));
        String remoteIp = blankToNull(alert.path("data").path("win").path("eventdata").path("ipAddress").asText(null));

        // Windows logons: the remote peer address lives in win.eventdata.ipAddress.
        // A logon with no remote address at all is local activity - skip it.
        if (srcIp == null && remoteIp == null) {
            return null;
        }
        // Loopback-only events (src or peer = 127.0.0.1, no real remote host)
        // are the machine talking to itself - not network activity.
        boolean loopbackSrc = LOOPBACK.equals(srcIp);
        boolean loopbackPeer = srcIp == null && LOOPBACK.equals(remoteIp);
        if (loopbackSrc || loopbackPeer) {
            return null;
        }

        String computer = alert.path("agent").path("name").asText("Unknown");
        JsonNode eventdata = alert.path("data").path("win").path("eventdata");
        String srcPort = cleanPort(firstNonBlank(
                alert.path("data").path("srcport").asText(null),
                eventdata.path("sourcePort").asText(null),
                eventdata.path("ipPort").asText(null)));
        String dstPort = cleanPort(firstNonBlank(
                alert.path("data").path("dstport").asText(null),
                eventdata.path("destPort").asText(null)));

        // SSH events do not carry an explicit protocol field; the port (22)
        // identifies it. Rules 100300/100301 come from Windows Event 5156, so
        // the transport is in win.eventdata.protocol. Otherwise N/A.
        String protocol = firstNonBlank(
                alert.path("data").path("protocol").asText(null),
                eventdata.path("protocol").asText(null),
                "22".equals(dstPort) ? "SSH" : null);

        String dstIp = firstNonBlank(
                alert.path("data").path("dstip").asText(null),
                eventdata.path("destAddress").asText(null),
                remoteIp);

        int level = rule.path("level").asInt(0);
        String severity = SecurityEventMapper.severityFromLevel(level);
        String description = rule.path("description").asText("");

        // Enrich with the real event details where present.
        String user = alert.path("data").path("dstuser").asText(null);
        if (user == null) {
            user = alert.path("data").path("win").path("eventdata").path("subjectUserName").asText(null);
        }
        if (user != null && !user.isBlank()) {
            description += " Account: " + user;
        }

        NetworkEvent event = new NetworkEvent(
                alert.path("id").asText(String.valueOf(System.nanoTime())),
                SecurityEventMapper.toIsoInstant(alert.path("timestamp").asText("")),
                computer,
                srcIp,
                dstIp,
                srcPort,
                dstPort,
                protocol,
                ruleId,
                NETWORK_TITLES.getOrDefault(ruleId, "Network event (rule " + ruleId + ")"),
                description.trim(),
                severity);

        // High/critical network alerts (brute force) reuse the existing
        // deduplicated email pipeline.
        notifyIfImportant(event);
        return event;
    }

    private void notifyIfImportant(NetworkEvent event) {
        SecurityEvent asSecurity = event.toSecurityEvent();
        if (notificationService.shouldNotify(asSecurity)) {
            notificationService.sendCriticalAlertEmail(asSecurity);
        }
    }

    /** Blank strings and "0" ports carry no network meaning -> null -> N/A. */
    private static String cleanPort(String port) {
        if (port == null || port.isBlank() || "0".equals(port.trim())) {
            return null;
        }
        return port.trim();
    }

    private static String blankToNull(String value) {
        return (value == null || value.isBlank()) ? null : value;
    }

    /**
     * Returns the first value that is neither null nor blank, or null when
     * every candidate is blank. Varargs so callers can list any number of
     * fallback fields (data.srcip, then win.eventdata.sourceAddress, ...).
     */
    private static String firstNonBlank(String... values) {
        for (String value : values) {
            if (value != null && !value.isBlank()) {
                return value;
            }
        }
        return null;
    }
}
