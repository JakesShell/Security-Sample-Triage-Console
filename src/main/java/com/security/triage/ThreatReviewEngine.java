package com.security.triage;

import java.util.ArrayList;
import java.util.List;

public class ThreatReviewEngine {

    public ReviewResult review(SampleSubmission sample) {
        int score = 0;
        List<String> evidence = new ArrayList<>(sample.getIndicators());

        if (!sample.isSigned()) {
            score += 18;
            evidence.add("Unsigned sample metadata increases trust risk.");
        }

        if (!sample.isKnownHash()) {
            score += 16;
            evidence.add("Hash is not present in the known-safe inventory.");
        }

        if (sample.isExternalSource()) {
            score += 12;
            evidence.add("Submission originated outside the trusted internal channel.");
        }

        if (sample.isMacroEnabled()) {
            score += 18;
            evidence.add("Macro-enabled document metadata requires analyst review.");
        }

        if (sample.isSuspiciousName()) {
            score += 14;
            evidence.add("Filename pattern matches suspicious naming heuristics.");
        }

        if (sample.isHighEntropyMetadata()) {
            score += 15;
            evidence.add("High-entropy metadata suggests the sample needs deeper review.");
        }

        score += Math.max(0, 20 - sample.getReputationScore());
        score += Math.max(0, 20 - sample.getPrevalenceScore());

        score = Math.min(100, score);

        String severity;
        String disposition;
        String queue;
        String recommendation;

        if (score >= 75) {
            severity = "Critical";
            disposition = "Escalate";
            queue = "Sandbox Priority Queue";
            recommendation = "Isolate the submission record, preserve evidence, and route to senior analyst review.";
        } else if (score >= 50) {
            severity = "High";
            disposition = "Manual Review";
            queue = "Analyst Review Queue";
            recommendation = "Review sample metadata and indicators before deciding whether to send to sandbox analysis.";
        } else if (score >= 25) {
            severity = "Medium";
            disposition = "Monitor";
            queue = "Triage Watchlist";
            recommendation = "Keep the record under monitoring and compare against future submissions.";
        } else {
            severity = "Low";
            disposition = "Archive";
            queue = "Passive Archive";
            recommendation = "Archive as low-risk metadata unless new indicators appear.";
        }

        return new ReviewResult(
                sample.getId(),
                sample.getFileName(),
                score,
                severity,
                disposition,
                queue,
                recommendation,
                evidence
        );
    }
}
