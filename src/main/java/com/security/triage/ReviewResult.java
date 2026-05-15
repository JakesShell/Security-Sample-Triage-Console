package com.security.triage;

import java.util.List;

public class ReviewResult {
    private final String sampleId;
    private final String fileName;
    private final int riskScore;
    private final String severity;
    private final String disposition;
    private final String queue;
    private final String recommendation;
    private final List<String> evidence;

    public ReviewResult(
            String sampleId,
            String fileName,
            int riskScore,
            String severity,
            String disposition,
            String queue,
            String recommendation,
            List<String> evidence
    ) {
        this.sampleId = sampleId;
        this.fileName = fileName;
        this.riskScore = riskScore;
        this.severity = severity;
        this.disposition = disposition;
        this.queue = queue;
        this.recommendation = recommendation;
        this.evidence = List.copyOf(evidence);
    }

    public String getSampleId() {
        return sampleId;
    }

    public String getFileName() {
        return fileName;
    }

    public int getRiskScore() {
        return riskScore;
    }

    public String getSeverity() {
        return severity;
    }

    public String getDisposition() {
        return disposition;
    }

    public String getQueue() {
        return queue;
    }

    public String getRecommendation() {
        return recommendation;
    }

    public List<String> getEvidence() {
        return evidence;
    }
}
