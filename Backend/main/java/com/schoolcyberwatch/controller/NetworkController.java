package com.schoolcyberwatch.controller;

import com.schoolcyberwatch.dto.NetworkEvent;
import com.schoolcyberwatch.service.NetworkMonitorService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * Network Monitoring endpoints (sixth detection category).
 *
 * Serves network-related Wazuh events (SSH activity, Windows network logons)
 * to the Network Monitoring page. Requires JWT like every other protected
 * endpoint; Wazuh credentials never leave the backend.
 */
@RestController
@RequestMapping("/api/network")
public class NetworkController {

    private final NetworkMonitorService networkMonitorService;

    public NetworkController(NetworkMonitorService networkMonitorService) {
        this.networkMonitorService = networkMonitorService;
    }

    /** Recent network events, newest first. */
    @GetMapping("/events")
    public List<NetworkEvent> getEvents(@RequestParam(defaultValue = "200") int limit) {
        return networkMonitorService.getRecentEvents(limit);
    }

    /** Counts for the Network Monitoring summary cards. */
    @GetMapping("/summary")
    public NetworkMonitorService.NetworkSummary getSummary() {
        return networkMonitorService.getSummary();
    }
}
