package com.schoolcyberwatch.service;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.time.Duration;
import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

class NetworkMonitorServiceTest {

    @Test
    @DisplayName("Dashboard network count uses an exact two-rule Indexer count over its window")
    void countsSchoolNetworkRulesWithoutFetchingEvents() {
        WazuhIndexerClient indexerClient = mock(WazuhIndexerClient.class);
        NotificationService notificationService = mock(NotificationService.class);
        when(indexerClient.countAlerts(eq("100300,100301"), anyString(), anyString(), isNull()))
                .thenReturn(24000L);
        NetworkMonitorService service = new NetworkMonitorService(indexerClient, notificationService, 72);

        assertEquals(24000L, service.countSchoolNetworkAlerts());

        ArgumentCaptor<String> since = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> until = ArgumentCaptor.forClass(String.class);
        verify(indexerClient).countAlerts(eq("100300,100301"), since.capture(), until.capture(), isNull());
        Duration window = Duration.between(Instant.parse(since.getValue()), Instant.parse(until.getValue()));
        assertTrue(window.compareTo(Duration.ofHours(72)) >= 0);
        assertTrue(window.compareTo(Duration.ofHours(72).plusSeconds(1)) < 0);
        verifyNoMoreInteractions(indexerClient);
        verifyNoInteractions(notificationService);
    }

    @Test
    @DisplayName("Network summary uses exact count/term aggregations over the 72h two-rule window")
    void summaryCountsExactlyWithoutFetchingEvents() {
        WazuhIndexerClient indexerClient = mock(WazuhIndexerClient.class);
        NotificationService notificationService = mock(NotificationService.class);
        when(indexerClient.countAlerts(eq("100300,100301"), anyString(), anyString(), isNull()))
                .thenReturn(590473L);
        when(indexerClient.countAlertsByLevel(eq("100300,100301"), anyString(), anyString()))
                .thenReturn(java.util.Map.of("5", 452222L, "10", 138251L));
        when(indexerClient.countAlertsByAgent(eq("100300,100301"), anyString(), anyString()))
                .thenReturn(java.util.Map.of("WIN-HUR37I74T1G", 590473L));
        NetworkMonitorService service = new NetworkMonitorService(indexerClient, notificationService, 72);

        NetworkMonitorService.NetworkSummary summary = service.getSummary();

        // Exact total, exact high-severity (level 10 -> High, level 5 -> Medium),
        // distinct endpoints from the agent aggregation key set.
        assertEquals(590473L, summary.totalEvents());
        assertEquals(138251L, summary.highSeverity());
        assertEquals(1L, summary.affectedEndpoints());
        assertEquals(72, summary.windowHours());
        assertEquals("exact", summary.countType());

        ArgumentCaptor<String> since = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> until = ArgumentCaptor.forClass(String.class);
        verify(indexerClient).countAlerts(eq("100300,100301"), since.capture(), until.capture(), isNull());
        Duration window = Duration.between(Instant.parse(since.getValue()), Instant.parse(until.getValue()));
        assertTrue(window.compareTo(Duration.ofHours(72)) >= 0);
        assertTrue(window.compareTo(Duration.ofHours(72).plusSeconds(1)) < 0);

        // Count questions must never download alert rows, and building the
        // summary must never reach the email pipeline.
        verify(indexerClient).countAlertsByLevel(eq("100300,100301"), anyString(), anyString());
        verify(indexerClient).countAlertsByAgent(eq("100300,100301"), anyString(), anyString());
        verify(indexerClient, never()).searchAlerts(anyString(), anyString(), org.mockito.ArgumentMatchers.anyInt());
        verifyNoMoreInteractions(indexerClient);
        verifyNoInteractions(notificationService);
    }
}