package com.schoolcyberwatch.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.schoolcyberwatch.dto.SecurityEvent;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests for the Wazuh alert -> School CyberWatch SecurityEvent mapping.
 * Uses representative sample JSON only - no live Wazuh needed for these.
 */
class SecurityEventMapperTest {

    private final SecurityEventMapper mapper = new SecurityEventMapper();
    private final ObjectMapper json = new ObjectMapper();

    private JsonNode alert(String raw) throws Exception {
        return json.readTree(raw);
    }

    @Test
    @DisplayName("Rule 60122 maps to FAILED_LOGIN with account name")
    void mapsFailedLogin() throws Exception {
        SecurityEvent event = mapper.fromWazuhAlert(alert("""
            {"id":"alert-1","timestamp":"2026-09-15T15:09:58.576+0000",
             "agent":{"id":"001","name":"WIN-HUR37I74T1G","ip":"192.168.56.103"},
             "rule":{"id":60122,"level":5,"description":"Windows logon failure."},
             "data":{"win":{"eventdata":{"subjectUserName":"student01"}}}}
            """));
        assertNotNull(event);
        assertEquals("FAILED_LOGIN", event.getType());
        assertEquals("60122", event.getRuleId());
        assertEquals("Medium", event.getSeverity());
        assertEquals("WIN-HUR37I74T1G", event.getComputer());
        assertEquals("001", event.getAgentId());
        assertEquals("student01", event.getUsername());
        assertEquals(5, event.getRuleLevel());
    }

    @Test
    @DisplayName("Rule 100200 maps to BRUTE_FORCE as Critical")
    void mapsBruteForce() throws Exception {
        SecurityEvent event = mapper.fromWazuhAlert(alert("""
            {"id":"alert-2","timestamp":"2026-09-15T15:10:00.000+0000",
             "agent":{"id":"001","name":"WIN-HUR37I74T1G"},
             "rule":{"id":100200,"level":12,"description":"Multiple Windows login failures."}}
            """));
        assertNotNull(event);
        assertEquals("BRUTE_FORCE", event.getType());
        assertEquals("Critical", event.getSeverity());
    }

    @Test
    @DisplayName("Rules 550/553 map to file integrity events with the file path")
    void mapsFileIntegrity() throws Exception {
        SecurityEvent modified = mapper.fromWazuhAlert(alert("""
            {"id":"alert-3","timestamp":"2026-09-15T15:11:00.000+0000",
             "agent":{"id":"001","name":"WIN-HUR37I74T1G"},
             "rule":{"id":550,"level":7,"description":"Integrity checksum changed."},
             "syscheck":{"path":"C:\\\\School\\\\Examinations\\\\marks.xlsx"}}
            """));
        assertNotNull(modified);
        assertEquals("FILE_MODIFIED", modified.getType());
        assertEquals("High", modified.getSeverity());
        assertEquals("C:\\School\\Examinations\\marks.xlsx", modified.getFilePath());
        assertTrue(modified.getDescription().contains("marks.xlsx"));

        SecurityEvent deleted = mapper.fromWazuhAlert(alert("""
            {"id":"alert-4","timestamp":"2026-09-15T15:12:00.000+0000",
             "agent":{"id":"001","name":"WIN-HUR37I74T1G"},
             "rule":{"id":553,"level":7,"description":"File deleted."},
             "syscheck":{"path":"C:\\\\School\\\\Examinations\\\\marks.xlsx"}}
            """));
        assertNotNull(deleted);
        assertEquals("FILE_DELETED", deleted.getType());
    }

    @Test
    @DisplayName("Rule 62123 maps to MALWARE_DETECTED with the Defender threat name")
    void mapsMalware() throws Exception {
        SecurityEvent event = mapper.fromWazuhAlert(alert("""
            {"id":"alert-5","timestamp":"2026-09-15T15:13:00.000+0000",
             "agent":{"id":"001","name":"WIN-HUR37I74T1G"},
             "rule":{"id":62123,"level":12,"description":"Malware detected."},
             "data":{"win":{"eventdata":{"threat Name":"EICAR Test File","path":"C:\\\\Temp\\\\eicar.com"}}}}
            """));
        assertNotNull(event);
        assertEquals("MALWARE_DETECTED", event.getType());
        assertEquals("Critical", event.getSeverity());
        assertEquals("EICAR Test File", event.getThreat());
        assertTrue(event.getDescription().contains("EICAR Test File"));
    }

    @Test
    @DisplayName("Rule 100300 maps to NETWORK_CONNECTION with win.eventdata source/destination")
    void mapsNetworkConnection() throws Exception {
        SecurityEvent event = mapper.fromWazuhAlert(alert("""
            {"id":"alert-6","timestamp":"2026-09-15T15:14:00.000+0000",
             "agent":{"id":"001","name":"WIN-HUR37I74T1G"},
             "rule":{"id":100300,"level":3,"description":"Inbound network connection."},
             "data":{"win":{"eventdata":{
               "sourceAddress":"192.168.56.104","sourcePort":"49152",
               "destAddress":"192.168.56.103","destPort":"445",
               "protocol":"TCP","direction":"inbound"}}}}
            """));
        assertNotNull(event);
        assertEquals("NETWORK_CONNECTION", event.getType());
        assertEquals("Low", event.getSeverity());
        assertEquals("192.168.56.104", event.getSourceIp());
        assertEquals("49152", event.getSourcePort());
        assertEquals("192.168.56.103", event.getDestinationIp());
        assertEquals("445", event.getDestinationPort());
    }

    @Test
    @DisplayName("Rule 100301 maps to NETWORK_SCAN and preserves the scanning source IP")
    void mapsNetworkScan() throws Exception {
        SecurityEvent event = mapper.fromWazuhAlert(alert("""
            {"id":"alert-7","timestamp":"2026-09-15T15:15:00.000+0000",
             "agent":{"id":"001","name":"WIN-HUR37I74T1G"},
             "rule":{"id":100301,"level":10,
                     "description":"School CyberWatch: Possible network scan detected from 192.168.56.104 - multiple inbound connections detected."},
             "data":{"win":{"eventdata":{
               "sourceAddress":"192.168.56.104","destAddress":"192.168.56.103",
               "destPort":"135","protocol":"TCP"}}}}
            """));
        assertNotNull(event);
        assertEquals("NETWORK_SCAN", event.getType());
        assertEquals("High", event.getSeverity());
        assertEquals("192.168.56.104", event.getSourceIp());
        assertEquals("192.168.56.103", event.getDestinationIp());
        assertTrue(event.getDescription().contains("192.168.56.104"));
    }

    @Test
    @DisplayName("Unmonitored rules are dropped (return null)")
    void dropsOtherRules() throws Exception {
        SecurityEvent event = mapper.fromWazuhAlert(alert("""
            {"id":"alert-8","timestamp":"2026-09-15T15:16:00.000+0000",
             "agent":{"id":"001","name":"WIN-HUR37I74T1G"},
             "rule":{"id":5551,"level":0,"description":"Some unrelated noise."}}
            """));
        assertNull(event);
    }

    @Test
    @DisplayName("Missing optional fields stay null - nothing is invented")
    void missingFieldsStayNull() throws Exception {
        SecurityEvent event = mapper.fromWazuhAlert(alert("""
            {"id":"alert-9","timestamp":"2026-09-15T15:17:00.000+0000",
             "agent":{"id":"001","name":"WIN-HUR37I74T1G"},
             "rule":{"id":60122,"level":5,"description":"Windows logon failure."}}
            """));
        assertNotNull(event);
        assertNull(event.getSourceIp());
        assertNull(event.getSourcePort());
        assertNull(event.getDestinationIp());
        assertNull(event.getDestinationPort());
        assertNull(event.getUsername());
        assertNull(event.getFilePath());
        assertNull(event.getThreat());
    }

    @Test
    @DisplayName("Severity boundaries follow the agreed level bands")
    void severityBands() {
        assertEquals("Low", SecurityEventMapper.severityFromLevel(0));
        assertEquals("Low", SecurityEventMapper.severityFromLevel(3));
        assertEquals("Medium", SecurityEventMapper.severityFromLevel(4));
        assertEquals("Medium", SecurityEventMapper.severityFromLevel(7 - 1));
        assertEquals("High", SecurityEventMapper.severityFromLevel(7));
        assertEquals("High", SecurityEventMapper.severityFromLevel(11));
        assertEquals("Critical", SecurityEventMapper.severityFromLevel(12));
        assertEquals("Critical", SecurityEventMapper.severityFromLevel(15));
    }

    @Test
    @DisplayName("Wazuh indexer timestamps (+0000 offset) are normalized to ISO instants")
    void normalizesTimestamps() {
        assertEquals("2026-09-15T15:09:58.576Z",
                SecurityEventMapper.toIsoInstant("2026-09-15T15:09:58.576+0000"));
        assertEquals("2026-09-15T15:09:58Z",
                SecurityEventMapper.toIsoInstant("2026-09-15T15:09:58Z"));
        // Unparseable input is passed through untouched, never dropped.
        assertEquals("not-a-date", SecurityEventMapper.toIsoInstant("not-a-date"));
    }

    @Test
    @DisplayName("The real Wazuh document id is preserved when present")
    void preservesWazuhDocumentId() throws Exception {
        SecurityEvent event = mapper.fromWazuhAlert(alert("""
            {"_id":"wazuh-doc-123","id":"alert-legacy-1","timestamp":"2026-09-15T15:18:00.000+0000",
             "agent":{"id":"001","name":"WIN-HUR37I74T1G"},
             "rule":{"id":60122,"level":5,"description":"Windows logon failure."}}
            """));
        assertNotNull(event);
        assertEquals("wazuh-doc-123", event.getId());
    }

    @Test
    @DisplayName("Network rule IDs classify into connection vs scan types")
    void networkTypeClassification() {
        assertEquals("NETWORK_CONNECTION", SecurityEventMapper.typeFromRule(100300));
        assertEquals("NETWORK_SCAN", SecurityEventMapper.typeFromRule(100301));
        assertFalse(SecurityEventMapper.typeFromRule(999999).equals("NETWORK_CONNECTION"));
    }
}
