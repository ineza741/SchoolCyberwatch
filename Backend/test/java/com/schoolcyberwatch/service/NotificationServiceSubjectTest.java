package com.schoolcyberwatch.service;

import com.schoolcyberwatch.dto.SecurityEvent;
import com.schoolcyberwatch.repository.NotificationLogRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.JavaMailSenderImpl;

import java.util.List;
import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import jakarta.mail.internet.MimeMessage;
import org.mockito.ArgumentCaptor;

/**
 * Unit tests for the per-type alert-email subject switch inside
 * NotificationService.sendCriticalAlertEmail. The JavaMailSender and the
 * NotificationLogRepository are mocked, so no SMTP server or database is
 * needed: the message is only BUILT here, never transmitted.
 */
class NotificationServiceSubjectTest {

    private static final String FROM = "ict@school.edu.rw";
    private static final String TO = "admin@school.edu.rw";

    private final JavaMailSender mailSender = mock(JavaMailSender.class);
    private final NotificationLogRepository logRepository = mock(NotificationLogRepository.class);

    private NotificationService serviceWithMailEnabled() {
        // A real (empty) MimeMessage can be built offline - it is never sent.
        when(mailSender.createMimeMessage())
                .thenReturn(new JavaMailSenderImpl().createMimeMessage());
        when(logRepository.existsByAlertId(any())).thenReturn(false);
        return new NotificationService(mailSender, logRepository, true, FROM, TO);
    }

    private SecurityEvent event(String type) {
        return new SecurityEvent("alert-subject-1", "2026-09-15T10:05:00Z", "WIN-HUR37I74T1G",
                type, "title", "Critical", "100200", "NEW", "test event");
    }

    private String subjectAfterSend(String type) throws Exception {
        NotificationService service = serviceWithMailEnabled();
        service.sendCriticalAlertEmail(event(type));

        ArgumentCaptor<MimeMessage> captor = ArgumentCaptor.forClass(MimeMessage.class);
        // The loop-based tests send several mails on the same mock; the one
        // this call just made is the last captured message.
        verify(mailSender, atLeastOnce()).send(captor.capture());
        List<MimeMessage> sent = captor.getAllValues();
        return sent.get(sent.size() - 1).getSubject();
    }

    @Test
    @DisplayName("Every alert type gets its own email subject")
    void subjectPerType() throws Exception {
        Map<String, String> expectedSubjects = Map.of(
                "MALWARE_DETECTED", "School CyberWatch - Malware Detection Alert",
                "NETWORK", "School CyberWatch - Network Security Alert",
                "NETWORK_SCAN", "School CyberWatch - Possible Network Scan Alert",
                "NETWORK_CONNECTION", "School CyberWatch - Network Connection Alert",
                "BRUTE_FORCE", "School CyberWatch - Brute-Force Attack Alert",
                "FILE_MODIFIED", "School CyberWatch - File Integrity Alert",
                "FILE_DELETED", "School CyberWatch - File Integrity Alert",
                "FAILED_LOGIN", "School CyberWatch - Failed Login Alert");

        for (Map.Entry<String, String> expected : expectedSubjects.entrySet()) {
            String subject = subjectAfterSend(expected.getKey());
            org.junit.jupiter.api.Assertions.assertEquals(
                    expected.getValue(), subject, "Wrong subject for type " + expected.getKey());
        }
    }

    @Test
    @DisplayName("Unknown or missing type uses the generic critical subject")
    void unknownTypeUsesGenericSubject() throws Exception {
        org.junit.jupiter.api.Assertions.assertEquals(
                "School CyberWatch - Critical Security Alert",
                subjectAfterSend("OTHER"));
        org.junit.jupiter.api.Assertions.assertEquals(
                "School CyberWatch - Critical Security Alert",
                subjectAfterSend(null));
    }

    @Test
    @DisplayName("Sent mail is addressed from the configured sender to the recipient")
    void mailIsAddressedCorrectly() throws Exception {
        NotificationService service = serviceWithMailEnabled();
        service.sendCriticalAlertEmail(event("BRUTE_FORCE"));

        ArgumentCaptor<MimeMessage> captor = ArgumentCaptor.forClass(MimeMessage.class);
        verify(mailSender).send(captor.capture());
        MimeMessage message = captor.getValue();

        org.junit.jupiter.api.Assertions.assertEquals(FROM, message.getFrom()[0].toString());
        org.junit.jupiter.api.Assertions.assertEquals(TO, message.getAllRecipients()[0].toString());
    }

        @Test
        @DisplayName("Only high and critical alerts are eligible for notification")
        void notificationThresholdExcludesRoutineNetworkConnections() {
        NotificationService service = new NotificationService(
            mailSender, logRepository, false, FROM, TO);
        SecurityEvent bruteForce = new SecurityEvent("alert-high", "2026-10-07T10:00:00Z",
            "WIN-HUR37I74T1G", "BRUTE_FORCE", "title", "Critical", "100200", "NEW", "desc");
        SecurityEvent networkScan = new SecurityEvent("alert-scan", "2026-10-07T10:00:00Z",
            "WIN-HUR37I74T1G", "NETWORK_SCAN", "title", "High", "100301", "NEW", "desc");
        SecurityEvent networkConnection = new SecurityEvent("alert-connection", "2026-10-07T10:00:00Z",
            "WIN-HUR37I74T1G", "NETWORK_CONNECTION", "title", "Medium", "100300", "NEW", "desc");

        org.junit.jupiter.api.Assertions.assertTrue(service.shouldNotify(bruteForce));
        org.junit.jupiter.api.Assertions.assertTrue(service.shouldNotify(networkScan));
        org.junit.jupiter.api.Assertions.assertFalse(service.shouldNotify(networkConnection));
        }

    @Test
    @DisplayName("An alert already notified is never emailed twice (dedup)")
    void duplicateAlertIsNotEmailed() {
        when(logRepository.existsByAlertId("alert-dup-1")).thenReturn(true);
        NotificationService service = new NotificationService(
                mailSender, logRepository, true, FROM, TO);

        service.sendCriticalAlertEmail(new SecurityEvent("alert-dup-1",
                "2026-09-15T10:05:00Z", "WIN-HUR37I74T1G", "BRUTE_FORCE", "title",
                "Critical", "100200", "NEW", "already sent"));

        verify(mailSender, never()).send(any(MimeMessage.class));
        verify(logRepository, never()).save(any());
    }

    @Test
    @DisplayName("Mail disabled means nothing is sent at all")
    void disabledMailSendsNothing() {
        NotificationService service = new NotificationService(
                mailSender, logRepository, false, FROM, TO);

        service.sendCriticalAlertEmail(event("BRUTE_FORCE"));

        verify(mailSender, never()).send(any(MimeMessage.class));
        verify(logRepository, never()).save(any());
    }
}
