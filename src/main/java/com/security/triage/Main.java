package com.security.triage;

import java.util.ArrayList;
import java.util.List;

public class Main {

    public static void main(String[] args) {
        List<SampleSubmission> submissions = buildSampleQueue();
        ThreatReviewEngine engine = new ThreatReviewEngine();

        int low = 0;
        int medium = 0;
        int high = 0;

        System.out.println("Threat Sample Review Client");
        System.out.println("Reviewing Submitted Samples");
        System.out.println();

        System.out.printf(
                "%-22s %-18s %-8s %-10s %-10s %-8s %-8s %-10s %-14s%n",
                "Sample",
                "Source Team",
                "Type",
                "RepScore",
                "BehScore",
                "Signed",
                "Macros",
                "NetIOC",
                "Severity"
        );
        System.out.println("----------------------------------------------------------------------------------------------------------------");

        for (SampleSubmission sample : submissions) {
            ReviewResult result = engine.review(sample);

            System.out.printf(
                    "%-22s %-18s %-8s %-10d %-10d %-8s %-8s %-10d %-14s%n",
                    sample.getSampleName(),
                    sample.getSourceTeam(),
                    sample.getFileType(),
                    sample.getReputationScore(),
                    sample.getBehaviorScore(),
                    sample.isSignedFile() ? "Yes" : "No",
                    sample.isMacroEnabled() ? "Yes" : "No",
                    sample.getNetworkIndicators(),
                    result.getSeverity()
            );
            System.out.println("Disposition: " + result.getDisposition());
            System.out.println("Recommendation: " + result.getRecommendation());
            System.out.println();

            switch (result.getSeverity()) {
                case "High" -> high++;
                case "Medium" -> medium++;
                default -> low++;
            }
        }

        System.out.println("Summary");
        System.out.println("-------");
        System.out.println("Low Severity Samples: " + low);
        System.out.println("Medium Severity Samples: " + medium);
        System.out.println("High Severity Samples: " + high);
    }

    private static List<SampleSubmission> buildSampleQueue() {
        List<SampleSubmission> submissions = new ArrayList<>();

        submissions.add(new SampleSubmission("invoice_viewer.docm", "Finance", "docm", 82, 41, false, true, 2));
        submissions.add(new SampleSubmission("partner_report.pdf", "Legal", "pdf", 12, 8, true, false, 0));
        submissions.add(new SampleSubmission("agent_update.exe", "Support", "exe", 90, 76, false, false, 7));
        submissions.add(new SampleSubmission("brand_assets.zip", "Marketing", "zip", 28, 18, true, false, 1));
        submissions.add(new SampleSubmission("macro_template.xlsm", "Operations", "xlsm", 55, 48, false, true, 4));

        return submissions;
    }
}
