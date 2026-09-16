package com.schoolcyberwatch.dto;

/**
 * A simplified School CyberWatch security event, transformed from a raw
 * Wazuh alert. Only the fields the dashboard needs are exposed - the huge
 * raw Wazuh JSON never reaches the frontend.
 *
 * The four monitored detections:
 *   rule 60122 -> FAILED_LOGIN
 *   rule 100200 -> BRUTE_FORCE
 *   rule 550   -> FILE_MODIFIED
 *   rule 553   -> FILE_DELETED
 */
public class SecurityEvent {

    private String id;
    private String timestamp;
    private String computer;
    private String type;
    private String title;
    private String severity;
    private String ruleId;
    private String status;
    private String description;

    public SecurityEvent() {
    }

    public SecurityEvent(String id, String timestamp, String computer, String type,
                         String title, String severity, String ruleId, String status,
                         String description) {
        this.id = id;
        this.timestamp = timestamp;
        this.computer = computer;
        this.type = type;
        this.title = title;
        this.severity = severity;
        this.ruleId = ruleId;
        this.status = status;
        this.description = description;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(String timestamp) {
        this.timestamp = timestamp;
    }

    public String getComputer() {
        return computer;
    }

    public void setComputer(String computer) {
        this.computer = computer;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public String getTitle() {
        return title;
    }

    public void setTitle(String title) {
        this.title = title;
    }

    public String getSeverity() {
        return severity;
    }

    public void setSeverity(String severity) {
        this.severity = severity;
    }

    public String getRuleId() {
        return ruleId;
    }

    public void setRuleId(String ruleId) {
        this.ruleId = ruleId;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }
}
