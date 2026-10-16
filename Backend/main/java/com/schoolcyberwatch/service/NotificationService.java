package com.schoolcyberwatch.service;

import com.schoolcyberwatch.dto.SecurityEvent;
import com.schoolcyberwatch.model.NotificationLog;
import com.schoolcyberwatch.repository.NotificationLogRepository;
import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

/**
 * Sends critical-alert emails (rule 100200 brute force by default) and
 * records each sent notification so the same alert is never emailed twice.
 *
 * Configuration comes from environment variables - see env.example.properties:
 *   MAIL_ENABLED, MAIL_HOST, MAIL_PORT, MAIL_USERNAME, MAIL_PASSWORD,
 *   ALERT_RECIPIENT. For Gmail, MAIL_PASSWORD is a 16-character App Password
 *   (Google Account -> Security -> 2-Step Verification -> App passwords).
 */
@Service
public class NotificationService {

    private static final Logger log = LoggerFactory.getLogger(NotificationService.class);

    private final JavaMailSender mailSender;
    private final NotificationLogRepository notificationLogRepository;
    private final boolean enabled;
    private final String fromAddress;
    private final String recipient;

    public NotificationService(JavaMailSender mailSender,
                               NotificationLogRepository notificationLogRepository,
                               @Value("${app.notifications.enabled:false}") boolean enabled,
                               @Value("${spring.mail.username:}") String fromAddress,
                               @Value("${app.notifications.recipient:}") String recipient) {
        this.mailSender = mailSender;
        this.notificationLogRepository = notificationLogRepository;
        this.enabled = enabled;
        this.fromAddress = fromAddress;
        this.recipient = recipient;
    }

    /** True for severities that must always notify (brute force, malware, etc.). */
    public boolean shouldNotify(SecurityEvent event) {
        return "Critical".equalsIgnoreCase(event.getSeverity())
                || "High".equalsIgnoreCase(event.getSeverity());
    }

    /**
     * Sends the alert email unless it was already sent or mail is disabled.
     * Safe to call on every dashboard refresh.
     */
    @Async
    public void sendCriticalAlertEmail(SecurityEvent event) {
        if (!enabled) {
            log.info("Mail disabled - would notify about {} on {} (rule {})",
                    event.getTitle(), event.getComputer(), event.getRuleId());
            return;
        }
        if (notificationLogRepository.existsByAlertId(event.getId())) {
            return;
        }
        try {
            String subject = switch (event.getType() == null ? "" : event.getType()) {
                case "MALWARE_DETECTED" -> "School CyberWatch - Malware Detection Alert";
                case "NETWORK" -> "School CyberWatch - Network Security Alert";
                case "NETWORK_SCAN" -> "School CyberWatch - Possible Network Scan Alert";
                case "NETWORK_CONNECTION" -> "School CyberWatch - Network Connection Alert";
                case "BRUTE_FORCE" -> "School CyberWatch - Brute-Force Attack Alert";
                case "FILE_MODIFIED", "FILE_DELETED" -> "School CyberWatch - File Integrity Alert";
                case "FAILED_LOGIN" -> "School CyberWatch - Failed Login Alert";
                default -> "School CyberWatch - Critical Security Alert";
            };
            String body = buildBody(event);
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, false, "UTF-8");
            helper.setFrom(fromAddress);
            helper.setTo(recipient);
            helper.setSubject(subject);
            helper.setText(body);
            mailSender.send(message);

            NotificationLog logEntry = new NotificationLog();
            logEntry.setAlertId(event.getId());
            logEntry.setSubject(subject);
            logEntry.setRecipient(recipient);
            notificationLogRepository.save(logEntry);
            log.info("Critical alert email sent for alert {} ({})", event.getId(), event.getTitle());
        } catch (MessagingException e) {
            log.error("Could not build alert email: {}", e.getMessage());
        } catch (org.springframework.mail.MailException e) {
            log.error("Could not send alert email: {}", e.getMessage());
        }
    }

    /**
     * Sends a test email so the team can verify SMTP settings from the UI
     * without waiting for a real attack. Not deduplicated.
     */
    public String sendTestEmail() {
        if (!enabled) {
            throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE,
                    "Email notifications are disabled (set MAIL_ENABLED=true, MAIL_USERNAME, MAIL_PASSWORD, ALERT_RECIPIENT).");
        }
        if (recipient == null || recipient.isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "No recipient configured (set ALERT_RECIPIENT).");
        }
        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, false, "UTF-8");
            helper.setFrom(fromAddress);
            helper.setTo(recipient);
            helper.setSubject("School CyberWatch - Test notification");
            helper.setText("This is a test notification from School CyberWatch. "
                    + "If you received this message, email alerts are configured correctly.");
            mailSender.send(message);
            return "Test email sent to " + recipient;
        } catch (MessagingException | org.springframework.mail.MailException e) {
            throw new ResponseStatusException(HttpStatus.BAD_GATEWAY,
                    "Could not send test email: " + e.getMessage());
        }
    }

    static String buildBody(SecurityEvent event) {
        String intro = switch (event.getType() == null ? "" : event.getType()) {
            case "MALWARE_DETECTED" -> "School CyberWatch detected a malware-related security event.";
            case "NETWORK" -> "School CyberWatch detected a network-related security event.";
            case "NETWORK_SCAN" -> "School CyberWatch detected a possible network scan against a monitored computer.";
            case "NETWORK_CONNECTION" -> "School CyberWatch recorded an inbound network connection on a monitored computer.";
            case "BRUTE_FORCE" -> "Possible brute-force attack detected.";
            case "FILE_MODIFIED" -> "A protected file was modified on a monitored computer.";
            case "FILE_DELETED" -> "A protected file was deleted on a monitored computer.";
            case "FAILED_LOGIN" -> "Repeated failed login attempts were detected.";
            default -> "A security event was detected.";
        };
        StringBuilder body = new StringBuilder(String.format(
                intro + "%n%n"
                        + "Computer: %s%n"
                        + "Severity: %s%n"
                        + "Time: %s%n"
                        + "Rule ID: %s%n%n"
                        + "%s%n%n"
                        + "Please open School CyberWatch for additional details.",
                event.getComputer(),
                event.getSeverity(),
                SecurityEventMapper.fullTime(event.getTimestamp()),
                event.getRuleId(),
                event.getDescription() == null ? "" : event.getDescription()));
        // Real network context when the alert carries it (rules 100300/100301).
        if (event.getSourceIp() != null) {
            body.append(String.format("%n%nSource: %s", event.getSourceIp()));
            if (event.getDestinationIp() != null) {
                body.append(String.format(" -> Destination: %s", event.getDestinationIp()))
                        .append(String.format(
                                "%nIf this source address is unknown, block it at the school firewall."));
            }
        }
        return body.toString();
    }
}
