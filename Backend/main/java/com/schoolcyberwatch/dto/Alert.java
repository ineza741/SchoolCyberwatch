package com.schoolcyberwatch.dto;

public class Alert {
    private Integer id;
    private String name;
    private String device;
    private String severity;
    private String time;
    private String status;

    public Alert(Integer id, String name, String device, String severity, String time, String status) {
        this.id = id;
        this.name = name;
        this.device = device;
        this.severity = severity;
        this.time = time;
        this.status = status;
    }

    public Integer getId() {
        return id;
    }

    public void setId(Integer id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getDevice() {
        return device;
    }

    public void setDevice(String device) {
        this.device = device;
    }

    public String getSeverity() {
        return severity;
    }

    public void setSeverity(String severity) {
        this.severity = severity;
    }

    public String getTime() {
        return time;
    }

    public void setTime(String time) {
        this.time = time;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }
}
