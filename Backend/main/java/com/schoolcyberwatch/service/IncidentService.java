package com.schoolcyberwatch.service;

import com.schoolcyberwatch.dto.IncidentDto;
import com.schoolcyberwatch.model.Incident;
import com.schoolcyberwatch.model.IncidentNote;
import com.schoolcyberwatch.repository.IncidentRepository;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.time.Instant;
import java.util.List;

/**
 * Incident management: create from an alert, view, change status,
 * add notes, resolve. Everything is persisted in the database.
 */
@Service
public class IncidentService {

    private final IncidentRepository incidentRepository;

    public IncidentService(IncidentRepository incidentRepository) {
        this.incidentRepository = incidentRepository;
    }

    @Transactional(readOnly = true)
    public List<IncidentDto> list(String status) {
        List<Incident> incidents = (status == null || status.isBlank())
                ? incidentRepository.findAllByOrderByCreatedAtDesc()
                : incidentRepository.findByStatusOrderByCreatedAtDesc(status.trim().toUpperCase());
        // Mapping (including lazy notes) happens inside the transaction/session.
        return incidents.stream().map(IncidentDto::new).toList();
    }

    @Transactional(readOnly = true)
    public IncidentDto get(Long id) {
        Incident incident = find(id);
        return new IncidentDto(incident);
    }

    @Transactional
    public IncidentDto create(String title, String description, String severity,
                              String sourceAlertId, String computer) {
        if (title == null || title.isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Incident title is required.");
        }
        Incident incident = new Incident();
        incident.setTitle(title.trim());
        incident.setDescription(description == null ? "" : description.trim());
        incident.setSeverity(normalizeSeverity(severity));
        incident.setSourceAlertId(sourceAlertId);
        incident.setComputer(computer);
        incident.setStatus(Incident.STATUS_OPEN);
        return new IncidentDto(incidentRepository.save(incident));
    }

    /** Allowed transitions: OPEN -> INVESTIGATING -> RESOLVED (and back). */
    @Transactional
    public IncidentDto changeStatus(Long id, String newStatus) {
        Incident incident = find(id);
        String normalized = newStatus == null ? "" : newStatus.trim().toUpperCase();
        if (!normalized.equals(Incident.STATUS_OPEN)
                && !normalized.equals(Incident.STATUS_INVESTIGATING)
                && !normalized.equals(Incident.STATUS_RESOLVED)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Unknown status: " + newStatus);
        }
        incident.setStatus(normalized);
        incident.setUpdatedAt(Instant.now());
        return new IncidentDto(incidentRepository.save(incident));
    }

    @Transactional
    public IncidentDto addNote(Long id, String note, String author) {
        if (note == null || note.isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Note text is required.");
        }
        Incident incident = find(id);
        IncidentNote incidentNote = new IncidentNote();
        incidentNote.setNote(note.trim());
        incidentNote.setAuthor(author == null || author.isBlank() ? "ICT administrator" : author.trim());
        incident.addNote(incidentNote);
        incident.setUpdatedAt(Instant.now());
        return new IncidentDto(incidentRepository.save(incident));
    }

    private Incident find(Long id) {
        return incidentRepository.findById(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Incident not found: " + id));
    }

    private String normalizeSeverity(String severity) {
        String value = severity == null || severity.isBlank() ? "Medium" : severity.trim();
        return value.substring(0, 1).toUpperCase() + value.substring(1).toLowerCase();
    }
}
