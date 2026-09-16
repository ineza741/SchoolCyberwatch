package com.schoolcyberwatch.dto;

public class DashboardSummary {
    private String label;
    private String value;
    private String tone;

    public DashboardSummary(String label, String value, String tone) {
        this.label = label;
        this.value = value;
        this.tone = tone;
    }

    public String getLabel() {
        return label;
    }

    public void setLabel(String label) {
        this.label = label;
    }

    public String getValue() {
        return value;
    }

    public void setValue(String value) {
        this.value = value;
    }

    public String getTone() {
        return tone;
    }

    public void setTone(String tone) {
        this.tone = tone;
    }
}
