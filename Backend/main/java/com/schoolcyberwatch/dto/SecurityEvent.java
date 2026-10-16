package com.schoolcyberwatch.dto;

/**
 * A simplified School CyberWatch security event, transformed from a raw
 * Wazuh alert. Only the fields the dashboard needs are exposed - the huge
 * raw Wazuh JSON never reaches the frontend.
 *
 * Monitored detections:
 *   rule 60122 -> FAILED_LOGIN
 *   rule 100200 -> BRUTE_FORCE
 *   rule 550   -> FILE_MODIFIED
 *   rule 553   -> FILE_DELETED
 *   rule 62123 -> MALWARE_DETECTED
 *   rule 100300 -> NETWORK_CONNECTION (plain inbound connection, not an attack)
 *   rule 100301 -> NETWORK_SCAN (correlated possible scan)
 *
 * Fields Wazuh did not provide stay null - never invented.
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

    // --- Optional real Wazuh details (null when the event lacks them) ---
    private String agentId;
    private String agentIp;
    private Integer ruleLevel;
    private String sourceIp;
    private String sourcePort;
    private String destinationIp;
    private String destinationPort;
    private String username;
    private String filePath;
    private String threat;
    private String eventId;

    public SecurityEvent() {
    }

    /** Original constructor used across the codebase (notifications, network view). */
    public SecurityEvent(String id, String timestamp, String computer, String type,
                         String title, String severity, String ruleId, String status,
                         String description) {
        this(id, timestamp, computer, type, title, severity, ruleId, status, description,
                null, null, null, null, null, null, null, null, null, null, null);
    }

    /** Full constructor with the optional Wazuh details. */
    public SecurityEvent(String id, String timestamp, String computer, String type,
                         String title, String severity, String ruleId, String status,
                         String description,
                         String agentId, String agentIp, Integer ruleLevel,
                         String sourceIp, String sourcePort,
                         String destinationIp, String destinationPort,
                         String username, String filePath, String threat, String eventId) {
        this.id = id;
        this.timestamp = timestamp;
        this.computer = computer;
        this.type = type;
        this.title = title;
        this.severity = severity;
        this.ruleId = ruleId;
        this.status = status;
        this.description = description;
        this.agentId = agentId;
        this.agentIp = agentIp;
        this.ruleLevel = ruleLevel;
        this.sourceIp = sourceIp;
        this.sourcePort = sourcePort;
        this.destinationIp = destinationIp;
        this.destinationPort = destinationPort;
        this.username = username;
        this.filePath = filePath;
        this.threat = threat;
        this.eventId = eventId;
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

    public String getAgentId() {
        return agentId;
    }

    public void setAgentId(String agentId) {
        this.agentId = agentId;
    }

    public String getAgentIp() {
        return agentIp;
    }

    public void setAgentIp(String agentIp) {
        this.agentIp = agentIp;
    }

    public Integer getRuleLevel() {
        return ruleLevel;
    }

    public void setRuleLevel(Integer ruleLevel) {
        this.ruleLevel = ruleLevel;
    }

    public String getSourceIp() {
        return sourceIp;
    }

    public void setSourceIp(String sourceIp) {
        this.sourceIp = sourceIp;
    }

    public String getSourcePort() {
        return sourcePort;
    }

    public void setSourcePort(String sourcePort) {
        this.sourcePort = sourcePort;
    }

    public String getDestinationIp() {
        return destinationIp;
    }

    public void setDestinationIp(String destinationIp) {
        this.destinationIp = destinationIp;
    }

    public String getDestinationPort() {
        return destinationPort;
    }

    public void setDestinationPort(String destinationPort) {
        this.destinationPort = destinationPort;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getFilePath() {
        return filePath;
    }

    public void setFilePath(String filePath) {
        this.filePath = filePath;
    }

    public String getThreat() {
        return threat;
    }

    public void setThreat(String threat) {
        this.threat = threat;
    }

    public String getEventId() {
        return eventId;
    }

    public void setEventId(String eventId) {
        this.eventId = eventId;
    }
}
