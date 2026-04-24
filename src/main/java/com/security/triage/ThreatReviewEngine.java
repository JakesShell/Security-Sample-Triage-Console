package com.security.triage;

import java.util.ArrayList;
import java.util.List;

public class ThreatReviewEngine {

    public ReviewResult review(SampleSubmission sample) {
        int score = 0;
        List<String> reasons = new ArrayList<>();

        if (sample.getReputationScore() >= 70) {
            score += 30;
            reasons.add("High external reputation risk score");
        }

        if (sample.getBehaviorScore() >= 60) {
            score += 30;
            reasons.add("Strong suspicious behavior score");
        }

        if (!sample.isSignedFile()) {
            score += 10;
            reasons.add("Unsigned file");
        }

        if (sample.isMacroEnabled()) {
            score += 20;
            reasons.add("Macro-enabled content");
        }

        if (sample.getNetworkIndicators() >= 5) {
            score += 20;
            reasons.add("Multiple network indicators detected");
        }

        if ("exe".equalsIgnoreCase(sample.getFileType()) || "dll".equalsIgnoreCase(sample.getFileType())) {
            score += 10;
            reasons.add("Executable file type");
        }

        if (score >= 70) {
            return new ReviewResult(
                    "Escalate To Sandbox Queue",
                    "High",
                    String.join("; ", reasons)
            );
        }

        if (score >= 40) {
            return new ReviewResult(
                    "Manual Analyst Review",
                    "Medium",
                    String.join("; ", reasons)
            );
        }

        return new ReviewResult(
                "Archive For Monitoring",
                "Low",
                reasons.isEmpty() ? "No strong risk indicators detected" : String.join("; ", reasons)
        );
    }
}
