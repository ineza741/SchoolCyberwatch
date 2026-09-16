package com.schoolcyberwatch.controller;

import com.schoolcyberwatch.service.NotificationService;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * Allows the ICT administrator to verify the SMTP setup with one click
 * from the Reports/Settings area.
 */
@RestController
@RequestMapping("/api/notifications")
public class NotificationController {

    private final NotificationService notificationService;

    public NotificationController(NotificationService notificationService) {
        this.notificationService = notificationService;
    }

    @PostMapping("/test")
    public Map<String, String> sendTestEmail() {
        return Map.of("message", notificationService.sendTestEmail());
    }
}
