package com.schoolcyberwatch.config;

import com.schoolcyberwatch.service.AuthService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Creates the default ICT administrator on first startup so the team can
 * log in immediately. Credentials come from environment variables
 * (ADMIN_EMAIL / ADMIN_PASSWORD) - see env.example.properties.
 */
@Configuration
public class AdminBootstrap {

    @Bean
    ApplicationRunner bootstrapAdmin(AuthService authService,
                                     @Value("${app.bootstrap.admin-email}") String adminEmail,
                                     @Value("${app.bootstrap.admin-password}") String adminPassword) {
        return args -> authService.createAdminIfMissing(adminEmail, adminPassword);
    }
}
