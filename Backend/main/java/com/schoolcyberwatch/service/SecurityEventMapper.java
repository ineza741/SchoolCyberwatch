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
 * SecurityEvent format. Only the four monitored detections are mapped:
 *
 *   rule 60122 -> FAILED_LOGIN   (Windows logon failure)
 *   rule 100200 -> BRUTE_FORCE   (custom correlation rule, level 12)
 *   rule 550   -> FILE_MODIFIED  (integrity checksum changed)
 *   rule 553   -> FILE_DELETED   (monitored file deleted)
 */
@Component
public class SecurityEventMapper {

    private static final DateTimeFormatter TIME_FORMAT =
            DateTimeFormatter.ofPattern("HH:mm").withZone(ZoneId.systemDefault());
    private static final DateTimeFormatter FULL_FORMAT =
            DateTimeFormatter.ISO_INSTANT;

    /** Wazuh rule level -> simple severity label used by the dashboard. */
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

    static String typeFromRule(long ruleId) {
        switch ((int) ruleId) {
            case 60122:
                return "FAILED_LOGIN";
            case 100200:
                return "BRUTE_FORCE";
            case 550:
                return "FILE_MODIFIED";
            case 553:
                return "FILE_DELETED";
            default:
                return "OTHER";
        }
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
            default:
                return "Security event";
        }
    }

    /**
     * Maps one Wazuh alert object. Returns null when the alert is not one of
     * the four rules we display (the manager also emits low-level noise we
     * deliberately keep away from the school dashboard).
     */
    public SecurityEvent fromWazuhAlert(JsonNode alert) {
        JsonNode rule = alert.path("rule");
        long ruleId = rule.path("id").asLong(-1);
        String type = typeFromRule(ruleId);
        if ("OTHER".equals(type)) {
            return null;
        }

        String id = alert.path("id").asText(String.valueOf(System.nanoTime()));
        String timestamp = toIsoInstant(alert.path("timestamp").asText(""));
        String computer = alert.path("agent").path("name").asText("Unknown computer");
        int level = rule.path("level").asInt(0);
        String severity = severityFromLevel(level);

        // Human-friendly description built from the most useful fields.
        StringBuilder description = new StringBuilder(rule.path("description").asText(""));
        JsonNode syscheck = alert.path("syscheck");
        if (syscheck.has("path")) {
            description.append(" File: ").append(syscheck.path("path").asText());
        }
        JsonNode data = alert.path("data");
        if (data.has("win")) {
            String user = data.path("win").path("eventdata").path("subjectUserName").asText("");
            if (!user.isEmpty()) {
                description.append(" Account: ").append(user);
            }
        }

        return new SecurityEvent(
                id,
                timestamp,
                computer,
                type,
                titleFromRule(ruleId),
                severity,
                String.valueOf(ruleId),
                "NEW",
                description.toString().trim());
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
}
