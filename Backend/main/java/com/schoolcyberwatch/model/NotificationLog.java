package com.schoolcyberwatch.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.Instant;

/**
 * Records which Wazuh alerts already triggered an email so refreshing the
 * dashboard never sends the same alert twice.
 */
@Entity
@Table(name = "notifications")
public class NotificationLog {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /** Wazuh alert id (unique per alert). */
    @Column(nullable = false, unique = true, length = 64)
    private String alertId;

    @Column(nullable = false, length = 190)
    private String subject;

    @Column(length = 120)
    private String recipient;

    @Column(nullable = false)
    private Instant sentAt = Instant.now();

    public Long getId() {
        return id;
    }

    public String getAlertId() {
        return alertId;
    }

    public void setAlertId(String alertId) {
        this.alertId = alertId;
    }

    public String getSubject() {
        return subject;
    }

    public void setSubject(String subject) {
        this.subject = subject;
    }

    public String getRecipient() {
        return recipient;
    }

    public void setRecipient(String recipient) {
        this.recipient = recipient;
    }

    public Instant getSentAt() {
        return sentAt;
    }

    public void setSentAt(Instant sentAt) {
        this.sentAt = sentAt;
    }
}
