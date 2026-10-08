package com.schoolcyberwatch.service;

import com.schoolcyberwatch.dto.SecurityEvent;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Small in-memory analytics over already-mapped {@link SecurityEvent}s,
 * used by the dashboard statistics endpoint. Everything is computed from
 * real Wazuh data - no fake numbers anywhere.
 */
@Component
public class AlertStatsService {

    /** Per-type alert counts (types with zero events are included with 0). */
    public Map<String, Long> countByType(List<SecurityEvent> events) {
        Map<String, Long> counts = new LinkedHashMap<>();
        for (String type : SecurityEventMapper.knownTypes()) {
            counts.put(type, 0L);
        }
        for (SecurityEvent event : events) {
            counts.merge(event.getType(), 1L, Long::sum);
        }
        return counts;
    }

    /** Per-severity alert counts (all four labels included, 0 when absent). */
    public Map<String, Long> countBySeverity(List<SecurityEvent> events) {
        Map<String, Long> counts = new LinkedHashMap<>();
        for (String severity : List.of("Critical", "High", "Medium", "Low")) {
            counts.put(severity, 0L);
        }
        for (SecurityEvent event : events) {
            counts.merge(event.getSeverity(), 1L, Long::sum);
        }
        return counts;
    }

    /** Maps exact Wazuh rule aggregations to the dashboard's seven event types. */
    public Map<String, Long> countByType(Map<String, Long> countsByRule) {
        Map<String, Long> counts = new LinkedHashMap<>();
        counts.put("FAILED_LOGIN", countsByRule.getOrDefault("60122", 0L));
        counts.put("BRUTE_FORCE", countsByRule.getOrDefault("100200", 0L));
        counts.put("FILE_MODIFIED", countsByRule.getOrDefault("550", 0L));
        counts.put("FILE_DELETED", countsByRule.getOrDefault("553", 0L));
        counts.put("MALWARE_DETECTED", countsByRule.getOrDefault("62123", 0L));
        counts.put("NETWORK_CONNECTION", countsByRule.getOrDefault("100300", 0L));
        counts.put("NETWORK_SCAN", countsByRule.getOrDefault("100301", 0L));
        return counts;
    }

    /** Maps Indexer rule-level buckets to the alert mapper's severity bands. */
    public Map<String, Long> countBySeverityLevel(Map<String, Long> countsByLevel) {
        Map<String, Long> counts = new LinkedHashMap<>();
        for (String severity : List.of("Critical", "High", "Medium", "Low")) {
            counts.put(severity, 0L);
        }
        for (Map.Entry<String, Long> entry : countsByLevel.entrySet()) {
            try {
                String severity = SecurityEventMapper.severityFromLevel(Integer.parseInt(entry.getKey()));
                counts.merge(severity, entry.getValue(), Long::sum);
            } catch (NumberFormatException ignored) {
                // Ignore malformed aggregation keys rather than failing dashboard stats.
            }
        }
        return counts;
    }

    /** Produces a complete day series for the requested window, including empty days. */
    public Map<String, Long> completeDayCounts(Map<String, Long> countsByDay, int days) {
        Map<String, Long> counts = new LinkedHashMap<>();
        java.time.LocalDate today = java.time.LocalDate.now();
        for (int i = days - 1; i >= 0; i--) {
            String day = today.minusDays(i).toString();
            counts.put(day, countsByDay.getOrDefault(day, 0L));
        }
        return counts;
    }

    /**
     * Alert counts bucketed per day (ISO date, oldest first) over the given
     * window, for the "alerts over time" chart.
     */
    public Map<String, Long> countByDay(List<SecurityEvent> events, int days) {
        Map<String, Long> counts = new LinkedHashMap<>();
        java.time.LocalDate today = java.time.LocalDate.now();
        for (int i = days - 1; i >= 0; i--) {
            counts.put(today.minusDays(i).toString(), 0L);
        }
        for (SecurityEvent event : events) {
            String day = dayKey(event.getTimestamp());
            if (day != null && counts.containsKey(day)) {
                counts.merge(day, 1L, Long::sum);
            }
        }
        return counts;
    }

    /** Newest-first sort by parsed timestamp (unparseable values go last). */
    public List<SecurityEvent> sortedNewestFirst(List<SecurityEvent> events) {
        List<SecurityEvent> sorted = new ArrayList<>(events);
        sorted.sort((a, b) -> {
            java.time.Instant ta = parse(a.getTimestamp());
            java.time.Instant tb = parse(b.getTimestamp());
            if (ta == null && tb == null) return 0;
            if (ta == null) return 1;
            if (tb == null) return -1;
            return tb.compareTo(ta);
        });
        return sorted;
    }

    /**
     * ISO day of the event timestamp, keyed in the same zone as the bucket
     * headers (system default). Using the UTC date here would move local
     * early-morning events onto the previous day and drop them at the
     * window edge.
     */
    static String dayKey(String isoTimestamp) {
        try {
            return java.time.LocalDate.ofInstant(
                    java.time.Instant.parse(isoTimestamp),
                    java.time.ZoneId.systemDefault()).toString();
        } catch (Exception e) {
            return null;
        }
    }

    private static java.time.Instant parse(String isoTimestamp) {
        try {
            return java.time.Instant.parse(isoTimestamp);
        } catch (Exception e) {
            return null;
        }
    }
}
