package com.schoolcyberwatch.exception;

/** Raised when an incident already exists for a Wazuh alert. */
public class IncidentConflictException extends RuntimeException {

    public IncidentConflictException() {
        super("An incident already exists for this security alert.");
    }
}