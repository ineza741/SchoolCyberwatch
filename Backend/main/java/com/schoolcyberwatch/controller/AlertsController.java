package com.schoolcyberwatch.controller;

import com.schoolcyberwatch.dto.SecurityEvent;
import com.schoolcyberwatch.service.WazuhService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * Security alerts page endpoint: real Wazuh events, transformed to the
 * simple School CyberWatch format.
 *
 * Supported query parameters (all optional):
 *   severity  Critical | High | Medium | Low
 *   type      FAILED_LOGIN | BRUTE_FORCE | FILE_MODIFIED | FILE_DELETED |
 *             MALWARE_DETECTED | NETWORK_CONNECTION | NETWORK_SCAN
 *   ruleId    exact Wazuh rule id (e.g. 60122, 100301)
 *   agent     Wazuh agent id (e.g. 001)
 *   from/to   ISO-8601 timestamps bounding the query window
 *   search    free text across computer, title, description, rule, user...
 *   limit     maximum number of events (1..500, default 200)
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
            @RequestParam(required = false) String ruleId,
            @RequestParam(required = false) String agent,
            @RequestParam(required = false) String from,
            @RequestParam(required = false) String to,
            @RequestParam(required = false) String search,
            @RequestParam(defaultValue = "200") int limit) {

        WazuhService.AlertFilter filter = new WazuhService.AlertFilter(
                type, severity, ruleId, agent, from, to, search, limit);
        return wazuhService.getAlerts(filter);
    }

    /** Single alert by its Wazuh alert id. 404 when the id is unknown. */
    @GetMapping("/{id}")
    public ResponseEntity<SecurityEvent> getAlert(@PathVariable String id) {
        SecurityEvent event = wazuhService.getAlertById(id);
        if (event == null) {
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.ok(event);
    }
}
