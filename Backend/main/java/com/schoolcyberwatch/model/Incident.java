package com.schoolcyberwatch.model;

import jakarta.persistence.CascadeType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.OneToMany;
import jakarta.persistence.Table;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * An incident is created by the ICT administrator from an important
 * security alert and tracked until it is resolved.
 * Statuses: OPEN, INVESTIGATING, RESOLVED.
 */
@Entity
@Table(name = "incidents")
public class Incident {

    public static final String STATUS_OPEN = "OPEN";
    public static final String STATUS_INVESTIGATING = "INVESTIGATING";
    public static final String STATUS_RESOLVED = "RESOLVED";

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, length = 190)
    private String title;

    @Column(length = 2000)
    private String description;

    @Column(nullable = false, length = 20)
    private String severity;

    @Column(nullable = false, length = 20)
    private String status = STATUS_OPEN;

    /** Wazuh alert id this incident was raised from (may be null). */
    @Column(name = "source_alert_id", length = 64)
    private String sourceAlertId;

    @Column(length = 120)
    private String computer;

    @Column(nullable = false)
    private Instant createdAt = Instant.now();

    @Column(nullable = false)
    private Instant updatedAt = Instant.now();

    @OneToMany(mappedBy = "incident", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<IncidentNote> notes = new ArrayList<>();

    public Long getId() {
        return id;
    }

    public String getTitle() {
        return title;
    }

    public void setTitle(String title) {
        this.title = title;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getSeverity() {
        return severity;
    }

    public void setSeverity(String severity) {
        this.severity = severity;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public String getSourceAlertId() {
        return sourceAlertId;
    }

    public void setSourceAlertId(String sourceAlertId) {
        this.sourceAlertId = sourceAlertId;
    }

    public String getComputer() {
        return computer;
    }

    public void setComputer(String computer) {
        this.computer = computer;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(Instant createdAt) {
        this.createdAt = createdAt;
    }

    public Instant getUpdatedAt() {
        return updatedAt;
    }

    public void setUpdatedAt(Instant updatedAt) {
        this.updatedAt = updatedAt;
    }

    public List<IncidentNote> getNotes() {
        return notes;
    }

    public void addNote(IncidentNote note) {
        note.setIncident(this);
        this.notes.add(note);
    }
}
