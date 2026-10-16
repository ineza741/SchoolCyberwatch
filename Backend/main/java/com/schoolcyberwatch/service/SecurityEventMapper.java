package com.schoolcyberwatch.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.schoolcyberwatch.dto.SecurityEvent;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeFormatterBuilder;
import java.time.temporal.ChronoField;

/**
 * Transforms raw Wazuh alert JSON into the simple School CyberWatch
 * SecurityEvent format. The monitored detections are:
 *
 *   rule 60122 -> FAILED_LOGIN        (Windows logon failure)
 *   rule 100200 -> BRUTE_FORCE        (custom correlation rule, level 12)
 *   rule 550   -> FILE_MODIFIED       (integrity checksum changed)
 *   rule 553   -> FILE_DELETED        (monitored file deleted)
 *   rule 62123 -> MALWARE_DETECTED    (Microsoft Defender malware detection)
 *   rule 100300 -> NETWORK_CONNECTION (custom inbound-connection rule - normal
 *                                      traffic, NOT labelled as an attack)
 *   rule 100301 -> NETWORK_SCAN       (custom correlated possible-scan rule)
 *
 * Mapping is done by rule ID (reliable), never by description text.
 * Note: Defender remediation events (rule 62124) are deliberately NOT mapped -
 * a threat and its cleanup must not count as two malware incidents.
 */
@Component
public class SecurityEventMapper {

    private static final DateTimeFormatter TIME_FORMAT =
            DateTimeFormatter.ofPattern("HH:mm").withZone(ZoneId.systemDefault());
    private static final DateTimeFormatter FULL_FORMAT =
            DateTimeFormatter.ISO_INSTANT;

    /** Wazuh rule level -> severity label used by the dashboard. */
    static String severityFromLevel(int level) {
        if (level >= 12) {
            return "Critical";
        }
        if (level >= 7) {
            return "High";
        }
        if (level >= 4) {
            return "Medium";
        }
        return "Low";
    }

    public static String typeFromRule(long ruleId) {
        switch ((int) ruleId) {
            case 60122:
                return "FAILED_LOGIN";
            case 100200:
                return "BRUTE_FORCE";
            case 550:
                return "FILE_MODIFIED";
            case 553:
                return "FILE_DELETED";
            case 62123:
                return "MALWARE_DETECTED";
            case 100300:
                return "NETWORK_CONNECTION";
            case 100301:
                return "NETWORK_SCAN";
            default:
                return "OTHER";
        }
    }

    /** All alert types the dashboard knows about, in display order. */
    public static java.util.List<String> knownTypes() {
        return java.util.List.of("FAILED_LOGIN", "BRUTE_FORCE", "FILE_MODIFIED",
                "FILE_DELETED", "MALWARE_DETECTED", "NETWORK_CONNECTION", "NETWORK_SCAN");
    }

    static String titleFromRule(long ruleId) {
        switch ((int) ruleId) {
            case 60122:
                return "Failed login";
            case 100200:
                return "Possible brute-force attack";
            case 550:
                return "Protected file modified";
            case 553:
                return "Protected file deleted";
            case 62123:
                return "Malware detected";
            case 100300:
                return "Inbound network connection";
            case 100301:
                return "Possible network scan";
            default:
                return "Security event";
        }
    }

    /**
     * Maps one Wazuh alert object. Returns null when the alert is not one of
     * the monitored rules (the manager also emits low-level noise we
     * deliberately keep away from the school dashboard).
     */
    public SecurityEvent fromWazuhAlert(JsonNode alert) {
        JsonNode rule = alert.path("rule");
        long ruleId = rule.path("id").asLong(-1);
        String type = typeFromRule(ruleId);
        if ("OTHER".equals(type)) {
            return null;
        }

        String id = firstNonBlank(alert.path("_id").asText(null), alert.path("id").asText(null));
        if (id == null || id.isBlank()) {
            id = String.valueOf(System.nanoTime());
        }
        String timestamp = toIsoInstant(alert.path("timestamp").asText(""));
        JsonNode agent = alert.path("agent");
        String computer = agent.path("name").asText("Unknown computer");
        int level = rule.path("level").asInt(0);
        String severity = severityFromLevel(level);

        JsonNode syscheck = alert.path("syscheck");
        JsonNode data = alert.path("data");
        JsonNode eventdata = data.path("win").path("eventdata");

        // Human-friendly description built from the most useful fields.
        StringBuilder description = new StringBuilder(rule.path("description").asText(""));
        if (syscheck.has("path")) {
            description.append(" File: ").append(syscheck.path("path").asText());
        }
        String user = eventdata.path("subjectUserName").asText("");
        if (!user.isEmpty()) {
            description.append(" Account: ").append(user);
        }
        // Malware alerts (rule 62123): use the real Defender threat fields.
        // Defender's field name is "threat Name" (with a space) in Wazuh events.
        String threatName = eventdata.path("threat Name").asText("");
        if (threatName.isEmpty()) {
            threatName = eventdata.path("threatName").asText("");
        }
        if (!threatName.isEmpty()) {
            description.append(" Threat: ").append(threatName);
        }
        String detectionPath = eventdata.path("path").asText("");
        if (!detectionPath.isEmpty()) {
            description.append(" Detected in: ").append(detectionPath);
        }

        // Network context: custom rules 100300/100301 carry win.eventdata
        // source/destination addresses and ports; stock Wazuh events may carry
        // data.srcip/dstip. Take whichever the event actually provides.
        String sourceIp = firstNonBlank(
                eventdata.path("sourceAddress").asText(null),
                data.path("srcip").asText(null));
        String destinationIp = firstNonBlank(
                eventdata.path("destAddress").asText(null),
                data.path("dstip").asText(null));
        String sourcePort = cleanPort(firstNonBlank(
                eventdata.path("sourcePort").asText(null),
                data.path("srcport").asText(null)));
        String destinationPort = cleanPort(firstNonBlank(
                eventdata.path("destPort").asText(null),
                data.path("dstport").asText(null)));

        return new SecurityEvent(
                id,
                timestamp,
                computer,
                type,
                titleFromRule(ruleId),
                severity,
                String.valueOf(ruleId),
                "NEW",
                description.toString().trim(),
                agent.path("id").asText(null),
                agent.path("ip").asText(null),
                level,
                sourceIp,
                sourcePort,
                destinationIp,
                destinationPort,
                user.isEmpty() ? null : user,
                syscheck.path("path").asText(null),
                threatName.isEmpty() ? null : threatName,
                blankToNull(eventdata.path("systemTime").asText(null)));
    }

    /**
     * Wazuh indexer timestamps look like "2026-09-15T15:09:58.576+0000",
     * which {@link Instant#parse} rejects (no colon in the offset). Normalize
     * to a real ISO instant ("...Z") so downstream parsing always works.
     */
    private static final DateTimeFormatter WAZUH_TIME = new DateTimeFormatterBuilder()
            .appendPattern("yyyy-MM-dd'T'HH:mm:ss")
            .optionalStart().appendFraction(ChronoField.NANO_OF_SECOND, 1, 9, true).optionalEnd()
            .appendPattern("XX")
            .toFormatter();

    static String toIsoInstant(String raw) {
        if (raw == null || raw.isBlank()) {
            return raw;
        }
        try {
            return Instant.parse(raw).toString();
        } catch (Exception ignored) {
            // fall through to the Wazuh indexer format
        }
        try {
            return OffsetDateTime.parse(raw, WAZUH_TIME).toInstant().toString();
        } catch (Exception e) {
            return raw;
        }
    }

    /** Short display time (HH:mm) used by dashboard tables. */
    public static String shortTime(String isoTimestamp) {
        try {
            return TIME_FORMAT.format(Instant.parse(isoTimestamp));
        } catch (Exception e) {
            return isoTimestamp == null ? "" : isoTimestamp;
        }
    }

    /** Full timestamp kept for detail views and reports. */
    public static String fullTime(String isoTimestamp) {
        try {
            return FULL_FORMAT.format(Instant.parse(isoTimestamp));
        } catch (Exception e) {
            return isoTimestamp == null ? "" : isoTimestamp;
        }
    }

    /** Blank strings and "0" ports carry no network meaning -> null. */
    private static String cleanPort(String port) {
        if (port == null || port.isBlank() || "0".equals(port.trim())) {
            return null;
        }
        return port.trim();
    }

    private static String blankToNull(String value) {
        return (value == null || value.isBlank()) ? null : value;
    }

    private static String firstNonBlank(String a, String b) {
        if (a != null && !a.isBlank()) {
            return a;
        }
        if (b != null && !b.isBlank()) {
            return b;
        }
        return null;
    }
}
