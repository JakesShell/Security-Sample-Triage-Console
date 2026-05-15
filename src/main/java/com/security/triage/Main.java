package com.security.triage;

import java.util.List;

public class Main {
    public static void main(String[] args) {
        ThreatReviewEngine engine = new ThreatReviewEngine();

        List<SampleSubmission> submissions = List.of(
                new SampleSubmission(
                        "SQ-1041",
                        "invoice-update.xlsm",
                        "Macro Document",
                        "External Email Gateway",
                        "Finance",
                        7,
                        9,
                        false,
                        false,
                        true,
                        true,
                        true,
                        true,
                        List.of("External sender", "Macro-enabled metadata", "Low prevalence")
                ),
                new SampleSubmission(
                        "SQ-1042",
                        "vpn-client-patch.exe",
                        "Executable",
                        "IT Service Desk",
                        "Infrastructure",
                        62,
                        74,
                        true,
                        true,
                        false,
                        false,
                        false,
                        false,
                        List.of("Signed vendor package", "Known deployment channel")
                ),
                new SampleSubmission(
                        "SQ-1043",
                        "q4-benefits-review.pdf",
                        "Document",
                        "HR Portal",
                        "Human Resources",
                        44,
                        51,
                        true,
                        true,
                        false,
                        false,
                        false,
                        false,
                        List.of("Known internal submission source", "Expected business context")
                ),
                new SampleSubmission(
                        "SQ-1044",
                        "client-payment-confirmation.scr",
                        "Screen Saver Binary",
                        "External Email Gateway",
                        "Accounts Receivable",
                        3,
                        6,
                        false,
                        false,
                        true,
                        false,
                        true,
                        true,
                        List.of("Unexpected executable-like extension", "External source", "Low reputation")
                )
        );

        System.out.println();
        System.out.println("SentinelQueue Threat Sample Intake And Triage Console");
        System.out.println("Simulation mode: metadata-only portfolio triage. No files are executed.");
        System.out.println("-----------------------------------------------------------------------");

        int critical = 0;
        int high = 0;
        int review = 0;

        for (SampleSubmission submission : submissions) {
            ReviewResult result = engine.review(submission);

            if ("Critical".equals(result.getSeverity())) {
                critical++;
            }

            if ("High".equals(result.getSeverity())) {
                high++;
            }

            if (!"Archive".equals(result.getDisposition())) {
                review++;
            }

            System.out.printf("%s | %-30s | Risk: %3d | %-8s | %-18s | %s%n",
                    result.getSampleId(),
                    result.getFileName(),
                    result.getRiskScore(),
                    result.getSeverity(),
                    result.getDisposition(),
                    result.getQueue()
            );
        }

        System.out.println("-----------------------------------------------------------------------");
        System.out.printf("Critical: %d | High: %d | Needs Review: %d | Total Samples: %d%n",
                critical,
                high,
                review,
                submissions.size()
        );
        System.out.println();
    }
}
