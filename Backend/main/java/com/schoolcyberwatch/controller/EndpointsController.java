package com.schoolcyberwatch.controller;

import com.schoolcyberwatch.dto.EndpointInfo;
import com.schoolcyberwatch.service.WazuhService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * Monitored computers (Wazuh agents) for the Computers page.
 */
@RestController
@RequestMapping("/api/endpoints")
public class EndpointsController {

    private final WazuhService wazuhService;

    public EndpointsController(WazuhService wazuhService) {
        this.wazuhService = wazuhService;
    }

    @GetMapping
    public List<EndpointInfo> getEndpoints() {
        return wazuhService.getAgents();
    }
}
