package com.schoolcyberwatch.controller;

import com.schoolcyberwatch.dto.Alert;
import com.schoolcyberwatch.dto.DashboardSummary;
import com.schoolcyberwatch.model.Incident;
import com.schoolcyberwatch.repository.IncidentRepository;
import com.schoolcyberwatch.service.SecurityEventMapper;
import com.schoolcyberwatch.service.WazuhService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.List;

/**
 * Dashboard endpoints backed by real Wazuh data.
 *
 * Summary cards follow the severity rules from the project spec:
 *   - brute force (rule 100200) counts as critical
 *   - file modified/deleted (550/553) count as high
 *   - failed login (60122) counts as medium
 */
@RestController
@RequestMapping("/api/dashboard")
public class DashboardController {

    private final WazuhService wazuhService;
    private final IncidentRepository incidentRepository;

    public DashboardController(WazuhService wazuhService, IncidentRepository incidentRepository) {
        this.wazuhService = wazuhService;
        this.incidentRepository = incidentRepository;
    }

    @GetMapping("/summary")
    public List<DashboardSummary> getSummary() {
        long computers = wazuhService.countAgents();
        long failedLogins = wazuhService.countAlerts("60122", null);
        long bruteForce = wazuhService.countAlerts("100200", null);
        long fileMods = wazuhService.countAlerts("550", null);
        long fileDels = wazuhService.countAlerts("553", null);
        long activeAlerts = failedLogins + bruteForce + fileMods + fileDels;
        long criticalHigh = bruteForce + fileMods + fileDels;

        List<DashboardSummary> cards = new ArrayList<>();
        cards.add(new DashboardSummary("Monitored computers", String.valueOf(computers), "neutral"));
        cards.add(new DashboardSummary("Active alerts", String.valueOf(activeAlerts), "violet"));
        cards.add(new DashboardSummary("Critical and high", String.valueOf(criticalHigh), "critical"));
        cards.add(new DashboardSummary("Open incidents",
                String.valueOf(incidentRepository.countByStatus(Incident.STATUS_OPEN)), "warning"));
        cards.add(new DashboardSummary("Resolved incidents",
                String.valueOf(incidentRepository.countByStatus(Incident.STATUS_RESOLVED)), "success"));
        return cards;
    }

    @GetMapping("/alerts")
    public List<Alert> getAlerts(@RequestParam(defaultValue = "10") int limit) {
        List<Alert> alerts = new ArrayList<>();
        for (com.schoolcyberwatch.dto.SecurityEvent event : wazuhService.getRecentAlerts(limit)) {
            alerts.add(new Alert(
                    Math.abs(event.getId().hashCode()),
                    event.getTitle(),
                    event.getComputer(),
                    event.getSeverity(),
                    SecurityEventMapper.shortTime(event.getTimestamp()),
                    event.getStatus()));
        }
        return alerts;
    }
}
