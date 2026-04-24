package com.security.triage;

public class ReviewResult {
    private final String disposition;
    private final String severity;
    private final String recommendation;

    public ReviewResult(String disposition, String severity, String recommendation) {
        this.disposition = disposition;
        this.severity = severity;
        this.recommendation = recommendation;
    }

    public String getDisposition() {
        return disposition;
    }

    public String getSeverity() {
        return severity;
    }

    public String getRecommendation() {
        return recommendation;
    }
}
