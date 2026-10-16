package com.schoolcyberwatch.controller;

import com.schoolcyberwatch.dto.Alert;
import com.schoolcyberwatch.dto.DashboardSummary;
import com.schoolcyberwatch.dto.SecurityEvent;
import com.schoolcyberwatch.model.Incident;
import com.schoolcyberwatch.repository.IncidentRepository;
import com.schoolcyberwatch.service.AlertStatsService;
import com.schoolcyberwatch.service.NetworkMonitorService;
import com.schoolcyberwatch.service.SecurityEventMapper;
import com.schoolcyberwatch.service.WazuhService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Dashboard endpoints backed by real Wazuh data.
 *
 * Summary cards follow the severity rules from the project spec:
 *   - brute force (rule 100200) counts as critical
 *   - malware detected (rule 62123) counts as critical (level 12)
 *   - network scan (rule 100301, level 10) counts as high
 *   - file modified/deleted (550/553) count as high
 *   - failed login (60122) counts as medium
 *   - plain network connections (rule 100300) are traffic, not attacks
 */
@RestController
@RequestMapping("/api/dashboard")
public class DashboardController {

    /** Window (days) for the statistics endpoint. */
    private static final int DEFAULT_STATS_DAYS = 7;
    private static final int MAX_STATS_DAYS = 90;

    private final WazuhService wazuhService;
    private final NetworkMonitorService networkMonitorService;
    private final AlertStatsService alertStatsService;
    private final IncidentRepository incidentRepository;

    public DashboardController(WazuhService wazuhService,
                               NetworkMonitorService networkMonitorService,
                               AlertStatsService alertStatsService,
                               IncidentRepository incidentRepository) {
        this.wazuhService = wazuhService;
        this.networkMonitorService = networkMonitorService;
        this.alertStatsService = alertStatsService;
        this.incidentRepository = incidentRepository;
    }

    @GetMapping("/summary")
    public List<DashboardSummary> getSummary() {
        long computers = wazuhService.countAgents();
        long failedLogins = wazuhService.countAlerts("60122", null);
        long bruteForce = wazuhService.countAlerts("100200", null);
        long fileMods = wazuhService.countAlerts("550", null);
        long fileDels = wazuhService.countAlerts("553", null);
        long malware = wazuhService.countAlerts("62123", null);
        long networkScans = wazuhService.countAlerts("100301", null);
        long network = networkMonitorService.countSchoolNetworkAlerts();
        long activeAlerts = failedLogins + bruteForce + fileMods + fileDels + malware + networkScans;
        // Network events overlap the primary rules (e.g. brute force with a
        // source IP) - they are a network *view*, so they are not added to this
        // card to avoid double counting.
        long criticalHigh = bruteForce + fileMods + fileDels + malware + networkScans;

        List<DashboardSummary> cards = new ArrayList<>();
        cards.add(new DashboardSummary("Monitored computers", String.valueOf(computers), "neutral"));
        cards.add(new DashboardSummary("Active alerts", String.valueOf(activeAlerts), "violet"));
        cards.add(new DashboardSummary("Critical and high", String.valueOf(criticalHigh), "critical"));
        cards.add(new DashboardSummary("Open incidents",
                String.valueOf(incidentRepository.countByStatus(Incident.STATUS_OPEN)), "warning"));
        cards.add(new DashboardSummary("Resolved incidents",
                String.valueOf(incidentRepository.countByStatus(Incident.STATUS_RESOLVED)), "success"));
        cards.add(new DashboardSummary("Network alerts",
                String.valueOf(network), "neutral"));
        return cards;
    }

    @GetMapping("/alerts")
    public List<Alert> getAlerts(@RequestParam(defaultValue = "10") int limit) {
        List<Alert> alerts = new ArrayList<>();
        for (SecurityEvent event : wazuhService.getRecentAlerts(limit)) {
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

    /**
     * Rich statistics for the dashboard charts, computed from real Wazuh
     * events over the given window (default 7 days, max 90):
     * totals per severity, per type, per day, plus per-detection counters.
     */
    @GetMapping("/stats")
    public Map<String, Object> getStats(@RequestParam(defaultValue = "7") int days) {
        int window = Math.min(Math.max(days, 1), MAX_STATS_DAYS);
        Instant until = Instant.now();
        String sinceIso = until.minus(Duration.ofDays(window)).toString();
        String untilIso = until.toString();

        Map<String, Long> countsByRule = wazuhService.countAlertsByRule(sinceIso, untilIso);
        Map<String, Long> countsByLevel = wazuhService.countAlertsByLevel(sinceIso, untilIso);
        Map<String, Long> countsByDay = wazuhService.countAlertsByDay(sinceIso, untilIso);
        Map<String, Long> bySeverity = alertStatsService.countBySeverityLevel(countsByLevel);
        Map<String, Long> byType = alertStatsService.countByType(countsByRule);
        List<SecurityEvent> recentAlerts = alertStatsService.sortedNewestFirst(
            wazuhService.getRecentAlerts(10));

        Map<String, Object> stats = new LinkedHashMap<>();
        stats.put("windowDays", window);
        stats.put("totalAlerts", countsByRule.values().stream().mapToLong(Long::longValue).sum());
        stats.put("bySeverity", bySeverity);
        stats.put("byType", byType);
        stats.put("overTime", alertStatsService.completeDayCounts(countsByDay, window));
        stats.put("recentAlerts", recentAlerts);
        return stats;
    }
}
