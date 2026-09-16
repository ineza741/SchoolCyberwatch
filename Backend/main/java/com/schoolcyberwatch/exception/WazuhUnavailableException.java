package com.schoolcyberwatch.exception;

/**
 * Thrown when the Wazuh Manager API cannot be reached or rejects our
 * credentials. The global exception handler converts this into HTTP 503
 * so the frontend can show a friendly "monitoring temporarily
 * unavailable" message instead of crashing.
 */
public class WazuhUnavailableException extends RuntimeException {

    public WazuhUnavailableException(String message) {
        super(message);
    }

    public WazuhUnavailableException(String message, Throwable cause) {
        super(message, cause);
    }
}
