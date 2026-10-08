package com.schoolcyberwatch.service;

import com.schoolcyberwatch.dto.SecurityEvent;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests for the dashboard statistics helpers - all numbers computed
 * from the mapped events only, zero-event categories still appear with 0.
 */
class AlertStatsServiceTest {

    private final AlertStatsService stats = new AlertStatsService();

    private SecurityEvent event(String type, String severity, String timestamp) {
        return new SecurityEvent("id-" + type + "-" + timestamp, timestamp, "WIN-HUR37I74T1G",
                type, "title", severity, "0", "NEW", "desc");
    }

    @Test
    @DisplayName("countByType includes every known type, zero when absent")
    void countByTypeIncludesZeroCategories() {
        Map<String, Long> counts = stats.countByType(List.of(
                event("FAILED_LOGIN", "Medium", "2026-09-15T10:00:00Z"),
                event("FAILED_LOGIN", "Medium", "2026-09-15T10:05:00Z"),
                event("NETWORK_SCAN", "High", "2026-09-15T10:10:00Z")));

        assertEquals(7, counts.size(), "all seven known types are reported");
        assertEquals(2L, counts.get("FAILED_LOGIN"));
        assertEquals(1L, counts.get("NETWORK_SCAN"));
        assertEquals(0L, counts.get("BRUTE_FORCE"));
        assertEquals(0L, counts.get("MALWARE_DETECTED"));
    }

    @Test
    @DisplayName("countBySeverity reports all four labels with zeros")
    void countBySeverityIncludesZeroLabels() {
        Map<String, Long> counts = stats.countBySeverity(List.of(
                event("BRUTE_FORCE", "Critical", "2026-09-15T10:00:00Z"),
                event("FILE_MODIFIED", "High", "2026-09-15T10:05:00Z")));

        assertEquals(1L, counts.get("Critical"));
        assertEquals(1L, counts.get("High"));
        assertEquals(0L, counts.get("Medium"));
        assertEquals(0L, counts.get("Low"));
    }

        @Test
        @DisplayName("Rule aggregation maps every monitored rule to its dashboard type")
        void countByTypeMapsRuleBuckets() {
                Map<String, Long> counts = stats.countByType(Map.of(
                                "60122", 3L, "100200", 2L, "550", 4L, "553", 5L,
                                "62123", 6L, "100300", 7L, "100301", 8L));

                assertEquals(3L, counts.get("FAILED_LOGIN"));
                assertEquals(2L, counts.get("BRUTE_FORCE"));
                assertEquals(4L, counts.get("FILE_MODIFIED"));
                assertEquals(5L, counts.get("FILE_DELETED"));
                assertEquals(6L, counts.get("MALWARE_DETECTED"));
                assertEquals(7L, counts.get("NETWORK_CONNECTION"));
                assertEquals(8L, counts.get("NETWORK_SCAN"));
        }

        @Test
        @DisplayName("Rule-level buckets aggregate into mapper severity bands")
        void countBySeverityMapsLevelBuckets() {
                Map<String, Long> counts = stats.countBySeverityLevel(Map.of(
                                "12", 2L, "10", 3L, "5", 4L, "2", 1L));

                assertEquals(2L, counts.get("Critical"));
                assertEquals(3L, counts.get("High"));
                assertEquals(4L, counts.get("Medium"));
                assertEquals(1L, counts.get("Low"));
        }

        @Test
        @DisplayName("Daily buckets include missing dates in the reporting window")
        void completeDayCountsFillsMissingDays() {
                java.time.LocalDate today = java.time.LocalDate.now();
                Map<String, Long> counts = stats.completeDayCounts(Map.of(today.toString(), 2L), 2);

                assertEquals(2, counts.size());
                assertEquals(0L, counts.get(today.minusDays(1).toString()));
                assertEquals(2L, counts.get(today.toString()));
        }

    @Test
    @DisplayName("countByDay buckets events per ISO day inside the window")
    void countByDayBuckets() {
        // The window rolls with "today", so build the fixtures relative to
        // now (noon keeps the calendar day stable across time zones).
        java.time.ZoneId zone = java.time.ZoneId.systemDefault();
        java.time.LocalDate yesterday = java.time.LocalDate.now(zone).minusDays(1);
        java.time.LocalDate today = java.time.LocalDate.now(zone);
        Map<String, Long> counts = stats.countByDay(List.of(
                event("FAILED_LOGIN", "Medium",
                        yesterday.atTime(12, 0).atZone(zone).toInstant().toString()),
                event("FAILED_LOGIN", "Medium",
                        yesterday.atTime(15, 30).atZone(zone).toInstant().toString()),
                event("NETWORK_SCAN", "High",
                        today.atTime(12, 0).atZone(zone).toInstant().toString())), 2);

        assertEquals(2, counts.size());
        assertEquals(2L, counts.get(yesterday.toString()));
        assertEquals(1L, counts.get(today.toString()));
    }

    @Test
    @DisplayName("Events outside the window are not counted in the buckets")
    void outsideWindowIgnored() {
        Map<String, Long> counts = stats.countByDay(List.of(
                event("FAILED_LOGIN", "Medium", "2020-01-01T00:00:00Z")), 3);
        assertTrue(counts.values().stream().allMatch(v -> v == 0L));
    }

    @Test
    @DisplayName("sortedNewestFirst puts the most recent event first")
    void newestFirstSorting() {
        List<SecurityEvent> sorted = stats.sortedNewestFirst(List.of(
                event("FAILED_LOGIN", "Medium", "2026-09-13T10:00:00Z"),
                event("NETWORK_SCAN", "High", "2026-09-15T10:00:00Z"),
                event("FILE_MODIFIED", "High", "2026-09-14T10:00:00Z")));

        assertEquals("2026-09-15T10:00:00Z", sorted.get(0).getTimestamp());
        assertEquals("2026-09-13T10:00:00Z", sorted.get(2).getTimestamp());
    }

    @Test
    @DisplayName("Unparseable timestamps sort last instead of breaking the order")
    void unparseableTimestampsGoLast() {
        List<SecurityEvent> sorted = stats.sortedNewestFirst(List.of(
                event("FAILED_LOGIN", "Medium", "not-a-date"),
                event("FAILED_LOGIN", "Medium", "2026-09-15T10:00:00Z")));

        assertEquals("2026-09-15T10:00:00Z", sorted.get(0).getTimestamp());
        assertEquals("not-a-date", sorted.get(1).getTimestamp());
    }
}
