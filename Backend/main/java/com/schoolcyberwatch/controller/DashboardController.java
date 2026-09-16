package com.schoolcyberwatch.controller;

import com.schoolcyberwatch.dto.Alert;
import com.schoolcyberwatch.dto.DashboardSummary;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("/api/dashboard")
public class DashboardController {

    @GetMapping("/summary")
    public List<DashboardSummary> getSummary() {
        return Arrays.asList(
            new DashboardSummary("Monitored computers", "24", "neutral"),
            new DashboardSummary("Active alerts", "8", "violet"),
            new DashboardSummary("Critical and high", "3", "critical"),
            new DashboardSummary("Open incidents", "2", "warning"),
            new DashboardSummary("Resolved incidents", "14", "success")
        );
    }

    @GetMapping("/alerts")
    public List<Alert> getAlerts() {
        return Arrays.asList(
            new Alert(1, "Possible brute force", "Examination-PC", "Critical", "10:35", "New"),
            new Alert(2, "Failed login", "Admin-PC", "Medium", "10:30", "New"),
            new Alert(3, "Protected file modified", "Examination-PC", "High", "09:45", "Investigating")
        );
    }
}
