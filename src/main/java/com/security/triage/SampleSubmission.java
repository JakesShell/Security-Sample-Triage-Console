package com.security.triage;

import java.util.List;
import java.util.Objects;

public class SampleSubmission {
    private final String id;
    private final String fileName;
    private final String fileType;
    private final String source;
    private final String businessUnit;
    private final int prevalenceScore;
    private final int reputationScore;
    private final boolean signed;
    private final boolean knownHash;
    private final boolean externalSource;
    private final boolean macroEnabled;
    private final boolean suspiciousName;
    private final boolean highEntropyMetadata;
    private final List<String> indicators;

    public SampleSubmission(
            String id,
            String fileName,
            String fileType,
            String source,
            String businessUnit,
            int prevalenceScore,
            int reputationScore,
            boolean signed,
            boolean knownHash,
            boolean externalSource,
            boolean macroEnabled,
            boolean suspiciousName,
            boolean highEntropyMetadata,
            List<String> indicators
    ) {
        this.id = Objects.requireNonNull(id);
        this.fileName = Objects.requireNonNull(fileName);
        this.fileType = Objects.requireNonNull(fileType);
        this.source = Objects.requireNonNull(source);
        this.businessUnit = Objects.requireNonNull(businessUnit);
        this.prevalenceScore = prevalenceScore;
        this.reputationScore = reputationScore;
        this.signed = signed;
        this.knownHash = knownHash;
        this.externalSource = externalSource;
        this.macroEnabled = macroEnabled;
        this.suspiciousName = suspiciousName;
        this.highEntropyMetadata = highEntropyMetadata;
        this.indicators = List.copyOf(indicators);
    }

    public String getId() {
        return id;
    }

    public String getFileName() {
        return fileName;
    }

    public String getFileType() {
        return fileType;
    }

    public String getSource() {
        return source;
    }

    public String getBusinessUnit() {
        return businessUnit;
    }

    public int getPrevalenceScore() {
        return prevalenceScore;
    }

    public int getReputationScore() {
        return reputationScore;
    }

    public boolean isSigned() {
        return signed;
    }

    public boolean isKnownHash() {
        return knownHash;
    }

    public boolean isExternalSource() {
        return externalSource;
    }

    public boolean isMacroEnabled() {
        return macroEnabled;
    }

    public boolean isSuspiciousName() {
        return suspiciousName;
    }

    public boolean isHighEntropyMetadata() {
        return highEntropyMetadata;
    }

    public List<String> getIndicators() {
        return indicators;
    }
}
