package com.schoolcyberwatch.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableAsync;

/**
 * Allows emails to be sent on a background thread so a slow SMTP server
 * never blocks dashboard requests.
 */
@Configuration
@EnableAsync
public class AsyncConfig {
}
