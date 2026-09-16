package com.schoolcyberwatch.dto;

/**
 * A monitored computer (Wazuh agent), simplified for the Computers page.
 */
public class EndpointInfo {

    private String id;
    private String name;
    private String ip;
    private String os;
    private String status;
    private String lastSeen;
    private String version;

    public EndpointInfo() {
    }

    public EndpointInfo(String id, String name, String ip, String os,
                        String status, String lastSeen, String version) {
        this.id = id;
        this.name = name;
        this.ip = ip;
        this.os = os;
        this.status = status;
        this.lastSeen = lastSeen;
        this.version = version;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getIp() {
        return ip;
    }

    public void setIp(String ip) {
        this.ip = ip;
    }

    public String getOs() {
        return os;
    }

    public void setOs(String os) {
        this.os = os;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public String getLastSeen() {
        return lastSeen;
    }

    public void setLastSeen(String lastSeen) {
        this.lastSeen = lastSeen;
    }

    public String getVersion() {
        return version;
    }

    public void setVersion(String version) {
        this.version = version;
    }
}
