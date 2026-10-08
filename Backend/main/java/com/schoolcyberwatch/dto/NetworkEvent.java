package com.schoolcyberwatch.dto;

import com.schoolcyberwatch.service.SecurityEventMapper;

/**
 * A network-related security event, normalized from a Wazuh alert for the
 * Network Monitoring page. Fields the Wazuh event does not provide are
 * "N/A" - never invented.
 *
 * category is "NETWORK" so the frontend can distinguish these from the
 * primary detections on the Security Alerts page. type carries the alert
 * class: NETWORK_CONNECTION (rule 100300, normal traffic) or NETWORK_SCAN
 * (rule 100301, possible scan); the attack-ish events keep their type
 * (BRUTE_FORCE, FAILED_LOGIN...).
 */
public class NetworkEvent {

    public static final String CATEGORY_NETWORK = "NETWORK";
    private static final String NA = "N/A";

    private String id;
    private String timestamp;
    private String computer;
    private String sourceIp;
    private String destinationIp;
    private String sourcePort;
    private String destinationPort;
    private String protocol;
    private String ruleId;
    private String title;
    private String description;
    private String severity;
    private String category;
    private String type;

    public NetworkEvent() {
    }

    public NetworkEvent(String id, String timestamp, String computer, String sourceIp,
                        String destinationIp, String sourcePort, String destinationPort,
                        String protocol, String ruleId, String title, String description,
                        String severity) {
        this.id = id;
        this.timestamp = timestamp;
        this.computer = computer;
        this.sourceIp = orNa(sourceIp);
        this.destinationIp = orNa(destinationIp);
        this.sourcePort = orNa(sourcePort);
        this.destinationPort = orNa(destinationPort);
        this.protocol = orNa(protocol);
        this.ruleId = ruleId;
        this.title = title;
        this.description = description;
        this.severity = severity;
        this.category = CATEGORY_NETWORK;
        // Classify by rule id: 100300 = plain connection, 100301 = scan,
        // otherwise fall back to the primary-detection type.
        if ("100301".equals(ruleId)) {
            this.type = "NETWORK_SCAN";
        } else if ("100300".equals(ruleId)) {
            this.type = "NETWORK_CONNECTION";
        } else {
            this.type = SecurityEventMapper.typeFromRule(safeParse(ruleId));
            if ("OTHER".equals(this.type)) {
                this.type = CATEGORY_NETWORK;
            }
        }
    }

    private static long safeParse(String ruleId) {
        try {
            return Long.parseLong(ruleId == null ? "" : ruleId.trim());
        } catch (NumberFormatException e) {
            return -1;
        }
    }

    /** Wazuh does not always provide every network field - show N/A, never fake values. */
    private static String orNa(String value) {
        return (value == null || value.isBlank()) ? NA : value;
    }

    /**
     * Converts this event into a SecurityEvent so high-severity network alerts
     * can reuse the existing email notification service and its deduplication.
     */
    public SecurityEvent toSecurityEvent() {
        return new SecurityEvent(id, timestamp, computer, CATEGORY_NETWORK,
                title, severity, ruleId, "NEW", description);
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

    public String getSourceIp() {
        return sourceIp;
    }

    public void setSourceIp(String sourceIp) {
        this.sourceIp = orNa(sourceIp);
    }

    public String getDestinationIp() {
        return destinationIp;
    }

    public void setDestinationIp(String destinationIp) {
        this.destinationIp = orNa(destinationIp);
    }

    public String getSourcePort() {
        return sourcePort;
    }

    public void setSourcePort(String sourcePort) {
        this.sourcePort = orNa(sourcePort);
    }

    public String getDestinationPort() {
        return destinationPort;
    }

    public void setDestinationPort(String destinationPort) {
        this.destinationPort = orNa(destinationPort);
    }

    public String getProtocol() {
        return protocol;
    }

    public void setProtocol(String protocol) {
        this.protocol = orNa(protocol);
    }

    public String getRuleId() {
        return ruleId;
    }

    public void setRuleId(String ruleId) {
        this.ruleId = ruleId;
    }

    public String getTitle() {
        return title;
    }

    public void setTitle(String title) {
        this.title = title;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getSeverity() {
        return severity;
    }

    public void setSeverity(String severity) {
        this.severity = severity;
    }

    public String getCategory() {
        return category;
    }

    public void setCategory(String category) {
        this.category = category;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }
}
