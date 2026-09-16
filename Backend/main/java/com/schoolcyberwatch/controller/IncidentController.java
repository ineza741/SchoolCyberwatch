package com.schoolcyberwatch.controller;

import com.schoolcyberwatch.dto.IncidentDto;
import com.schoolcyberwatch.service.IncidentService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;
import java.util.List;
import java.util.Map;

/**
 * Incident management API. All routes require authentication.
 */
@RestController
@RequestMapping("/api/incidents")
public class IncidentController {

    private final IncidentService incidentService;

    public IncidentController(IncidentService incidentService) {
        this.incidentService = incidentService;
    }

    @GetMapping
    public List<IncidentDto> list(@RequestParam(required = false) String status) {
        return incidentService.list(status);
    }

    @GetMapping("/{id}")
    public IncidentDto get(@PathVariable Long id) {
        return incidentService.get(id);
    }

    /** Body: { title, description, severity, sourceAlertId, computer } */
    @PostMapping
    public ResponseEntity<IncidentDto> create(@RequestBody Map<String, String> body) {
        IncidentDto created = incidentService.create(
                body.get("title"),
                body.get("description"),
                body.get("severity"),
                body.get("sourceAlertId"),
                body.get("computer"));
        return ResponseEntity.status(201).body(created);
    }

    /** Body: { status: OPEN | INVESTIGATING | RESOLVED } */
    @PostMapping("/{id}/status")
    public IncidentDto changeStatus(@PathVariable Long id, @RequestBody Map<String, String> body) {
        return incidentService.changeStatus(id, body.get("status"));
    }

    /** Body: { note: "...", author: "..." } */
    @PostMapping("/{id}/notes")
    public IncidentDto addNote(@PathVariable Long id, @RequestBody Map<String, String> body, Principal principal) {
        return incidentService.addNote(id, body.get("note"), principal == null ? null : principal.getName());
    }
}
