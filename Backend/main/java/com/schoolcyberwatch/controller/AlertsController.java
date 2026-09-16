package com.schoolcyberwatch.controller;

import com.schoolcyberwatch.dto.SecurityEvent;
import com.schoolcyberwatch.service.WazuhService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Security alerts page endpoint: real Wazuh events, transformed to the
 * simple School CyberWatch format, with basic filtering kept deliberately
 * simple (severity, type, computer text search) for the prototype.
 */
@RestController
@RequestMapping("/api/alerts")
public class AlertsController {

    private final WazuhService wazuhService;

    public AlertsController(WazuhService wazuhService) {
        this.wazuhService = wazuhService;
    }

    @GetMapping
    public List<SecurityEvent> getAlerts(
            @RequestParam(required = false) String severity,
            @RequestParam(required = false) String type,
            @RequestParam(required = false) String search,
            @RequestParam(defaultValue = "200") int limit) {

        List<SecurityEvent> events = wazuhService.getRecentAlerts(limit);
        List<SecurityEvent> filtered = new ArrayList<>();

        for (SecurityEvent event : events) {
            if (severity != null && !severity.isBlank()
                    && !event.getSeverity().equalsIgnoreCase(severity.trim())) {
                continue;
            }
            if (type != null && !type.isBlank()
                    && !event.getType().equalsIgnoreCase(type.trim())) {
                continue;
            }
            if (search != null && !search.isBlank()) {
                String needle = search.trim().toLowerCase(Locale.ROOT);
                boolean matches =
                        contains(event.getComputer(), needle)
                                || contains(event.getTitle(), needle)
                                || contains(event.getDescription(), needle)
                                || contains(event.getRuleId(), needle);
                if (!matches) {
                    continue;
                }
            }
            filtered.add(event);
        }
        return filtered;
    }

    private static boolean contains(String value, String needle) {
        return value != null && value.toLowerCase(Locale.ROOT).contains(needle);
    }
}
