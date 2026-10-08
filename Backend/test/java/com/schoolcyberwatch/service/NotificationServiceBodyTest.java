package com.schoolcyberwatch.service;

import com.schoolcyberwatch.dto.SecurityEvent;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests for the alert-email body built by NotificationService.buildBody.
 * Verifies the per-type intros, the required event fields, and that network
 * context (Source -> Destination, rules 100300/100301) is included only when
 * the event really carries it - never fabricated.
 */
class NotificationServiceBodyTest {

    private SecurityEvent event(String type, String severity, String ruleId, String description) {
        return new SecurityEvent("alert-1", "2026-09-15T10:05:00Z", "WIN-HUR37I74T1G",
                type, "title", severity, ruleId, "NEW", description);
    }

    @Test
    @DisplayName("Brute-force alerts use the brute-force intro and event fields")
    void bruteForceBody() {
        String body = NotificationService.buildBody(
                event("BRUTE_FORCE", "Critical", "100200", "12 failures in 60 seconds"));

        assertTrue(body.startsWith("Possible brute-force attack detected."));
        assertTrue(body.contains("Computer: WIN-HUR37I74T1G"));
        assertTrue(body.contains("Severity: Critical"));
        assertTrue(body.contains("Rule ID: 100200"));
        assertTrue(body.contains("12 failures in 60 seconds"));
    }

    @Test
    @DisplayName("Malware alerts use the malware intro")
    void malwareBody() {
        String body = NotificationService.buildBody(
                event("MALWARE_DETECTED", "Critical", "62123", "Trojan found"));

        assertTrue(body.startsWith(
                "School CyberWatch detected a malware-related security event."));
    }

    @Test
    @DisplayName("File integrity alerts distinguish modified from deleted")
    void fileIntegrityBodies() {
        assertTrue(NotificationService.buildBody(
                event("FILE_MODIFIED", "High", "550", "Exam.xlsx changed"))
                .startsWith("A protected file was modified on a monitored computer."));
        assertTrue(NotificationService.buildBody(
                event("FILE_DELETED", "High", "553", "Exam.xlsx removed"))
                .startsWith("A protected file was deleted on a monitored computer."));
    }

    @Test
    @DisplayName("Failed-login alerts use the failed-login intro")
    void failedLoginBody() {
        String body = NotificationService.buildBody(
                event("FAILED_LOGIN", "Medium", "60122", "Logon failure for student01"));

        assertTrue(body.startsWith("Repeated failed login attempts were detected."));
    }

    @Test
    @DisplayName("Network scan and connection alerts use their own intros")
    void networkRuleBodies() {
        assertTrue(NotificationService.buildBody(
                event("NETWORK_SCAN", "High", "100301", "Scan detected"))
                .startsWith("School CyberWatch detected a possible network scan against a monitored computer."));
        assertTrue(NotificationService.buildBody(
                event("NETWORK_CONNECTION", "Low", "100300", "Inbound connection"))
                .startsWith("School CyberWatch recorded an inbound network connection on a monitored computer."));
        assertTrue(NotificationService.buildBody(
                event("NETWORK", "High", "5760", "SSH brute force"))
                .startsWith("School CyberWatch detected a network-related security event."));
    }

    @Test
    @DisplayName("Unknown or missing type falls back to the generic intro")
    void unknownTypeFallsBack() {
        assertTrue(NotificationService.buildBody(
                event("OTHER", "Critical", "99999", "Unmapped rule"))
                .startsWith("A security event was detected."));
        assertTrue(NotificationService.buildBody(
                event(null, "Critical", "99999", "No type"))
                .startsWith("A security event was detected."));
    }

    @Test
    @DisplayName("Scan alert carries the real source and destination when present")
    void networkContextRendered() {
        SecurityEvent scan = event("NETWORK_SCAN", "High", "100301", "Scan detected");
        scan.setSourceIp("192.168.56.104");
        scan.setDestinationIp("192.168.56.103");

        String body = NotificationService.buildBody(scan);

        assertTrue(body.contains(
                "Source: 192.168.56.104 -> Destination: 192.168.56.103"));
        assertTrue(body.contains(
                "If this source address is unknown, block it at the school firewall."));
    }

    @Test
    @DisplayName("Source without destination shows the source only")
    void sourceOnlyContext() {
        SecurityEvent alert = event("BRUTE_FORCE", "Critical", "100200", "SSH attacks");
        alert.setSourceIp("192.168.56.104");

        String body = NotificationService.buildBody(alert);

        assertTrue(body.contains("Source: 192.168.56.104"));
        assertFalse(body.contains("-> Destination:"));
        assertFalse(body.contains("block it at the school firewall."));
    }

    @Test
    @DisplayName("No network context is invented when the event has no source IP")
    void noSourceNoContext() {
        SecurityEvent alert = event("BRUTE_FORCE", "Critical", "100200", "SSH attacks");
        alert.setDestinationIp("192.168.56.103"); // destination alone is not enough

        String body = NotificationService.buildBody(alert);

        assertFalse(body.contains("Source:"));
        assertFalse(body.contains("Destination:"));
        assertFalse(body.contains("block it at the school firewall."));
    }

    @Test
    @DisplayName("Unparseable timestamps pass through unchanged in the Time line")
    void timeLinePassthrough() {
        SecurityEvent alert = event("BRUTE_FORCE", "Critical", "100200", "SSH attacks");
        alert.setTimestamp("not-a-date");

        String body = NotificationService.buildBody(alert);

        assertTrue(body.contains("Time: not-a-date"));
    }
}
