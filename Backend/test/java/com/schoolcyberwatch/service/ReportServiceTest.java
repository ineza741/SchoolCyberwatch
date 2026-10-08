package com.schoolcyberwatch.service;

import com.lowagie.text.pdf.PdfReader;
import com.lowagie.text.pdf.parser.PdfTextExtractor;
import com.schoolcyberwatch.model.Incident;
import com.schoolcyberwatch.repository.IncidentRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class ReportServiceTest {

    @Test
    @DisplayName("PDF report includes exact seven-rule totals, severity and incident counts")
    void reportContainsExactAggregatedCounts() throws Exception {
        WazuhService wazuhService = mock(WazuhService.class);
        IncidentRepository incidentRepository = mock(IncidentRepository.class);
        Map<String, Long> countsByRule = Map.of(
                "60122", 2L,
                "100200", 3L,
                "550", 4L,
                "553", 5L,
                "62123", 6L,
                "100300", 7L,
                "100301", 8L);
        when(wazuhService.countAgents()).thenReturn(1L);
        when(wazuhService.countAlertsByRule(anyString(), anyString())).thenReturn(countsByRule);
        when(wazuhService.countAlertsByLevel(anyString(), anyString())).thenReturn(Map.of(
                "5", 9L, "7", 9L, "10", 8L, "12", 9L));
        when(incidentRepository.countByStatus(Incident.STATUS_OPEN)).thenReturn(1L);
        when(incidentRepository.countByStatus(Incident.STATUS_INVESTIGATING)).thenReturn(2L);
        when(incidentRepository.countByStatus(Incident.STATUS_RESOLVED)).thenReturn(3L);

        ReportService reportService = new ReportService(
                wazuhService, new AlertStatsService(), incidentRepository);
        PdfReader reader = new PdfReader(reportService.generateSecurityReport(30));
        try {
            StringBuilder reportText = new StringBuilder();
            PdfTextExtractor extractor = new PdfTextExtractor(reader);
            for (int page = 1; page <= reader.getNumberOfPages(); page++) {
                reportText.append(extractor.getTextFromPage(page));
            }
            String text = reportText.toString();

            assertTrue(text.contains("School CyberWatch - Security Report"));
            assertTrue(text.matches("(?s).*Network connections \\(rule 100300\\)\\s*7.*"));
            assertTrue(text.matches("(?s).*Possible network scans \\(rule 100301\\)\\s*8.*"), text);
            assertTrue(text.matches("(?s).*Total monitored alerts\\s*35.*"));
            assertTrue(text.contains("Critical: 9"));
            assertTrue(text.contains("High: 17"));
            assertTrue(text.contains("Medium: 9"));
            assertTrue(text.contains("Low: 0"));
            assertTrue(text.contains("Open incidents: 1"));
            assertTrue(text.contains("Investigating: 2"));
            assertTrue(text.contains("Resolved: 3"));
        } finally {
            reader.close();
        }
    }
}