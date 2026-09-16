package com.schoolcyberwatch.exception;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.Map;

/**
 * Central error translation. When Wazuh is unavailable the API returns 503
 * with a clear message so the dashboard can show
 * "Security monitoring service temporarily unavailable."
 * instead of crashing or silently showing fake data.
 */
@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(WazuhUnavailableException.class)
    public ResponseEntity<Map<String, String>> handleWazuhUnavailable(WazuhUnavailableException ex) {
        return ResponseEntity.status(503)
                .body(Map.of(
                        "error", "Security monitoring service temporarily unavailable.",
                        "detail", ex.getMessage() == null ? "" : ex.getMessage()));
    }
}
