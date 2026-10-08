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
}