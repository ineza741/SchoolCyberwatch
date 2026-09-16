package com.schoolcyberwatch.dto;

import com.schoolcyberwatch.model.Incident;
import com.schoolcyberwatch.model.IncidentNote;

import java.time.Instant;
import java.util.List;

/**
 * Incident as exposed to the frontend, including its notes.
 */
public class IncidentDto {

    private Long id;
    private String title;
    private String description;
    private String severity;
    private String status;
    private String sourceAlertId;
    private String computer;
    private Instant createdAt;
    private Instant updatedAt;
    private List<NoteDto> notes;

    public static class NoteDto {
        private Long id;
        private String note;
        private String author;
        private Instant createdAt;

        public NoteDto(IncidentNote note) {
            this.id = note.getId();
            this.note = note.getNote();
            this.author = note.getAuthor();
            this.createdAt = note.getCreatedAt();
        }

        public Long getId() {
            return id;
        }

        public String getNote() {
            return note;
        }

        public String getAuthor() {
            return author;
        }

        public Instant getCreatedAt() {
            return createdAt;
        }
    }

    public IncidentDto(Incident incident) {
        this.id = incident.getId();
        this.title = incident.getTitle();
        this.description = incident.getDescription();
        this.severity = incident.getSeverity();
        this.status = incident.getStatus();
        this.sourceAlertId = incident.getSourceAlertId();
        this.computer = incident.getComputer();
        this.createdAt = incident.getCreatedAt();
        this.updatedAt = incident.getUpdatedAt();
        this.notes = incident.getNotes() == null
                ? List.of()
                : incident.getNotes().stream().map(NoteDto::new).toList();
    }

    public Long getId() {
        return id;
    }

    public String getTitle() {
        return title;
    }

    public String getDescription() {
        return description;
    }

    public String getSeverity() {
        return severity;
    }

    public String getStatus() {
        return status;
    }

    public String getSourceAlertId() {
        return sourceAlertId;
    }

    public String getComputer() {
        return computer;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public Instant getUpdatedAt() {
        return updatedAt;
    }

    public List<NoteDto> getNotes() {
        return notes;
    }
}
