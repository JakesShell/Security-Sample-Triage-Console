package com.security.triage;

public class SampleSubmission {
    private final String sampleName;
    private final String sourceTeam;
    private final String fileType;
    private final int reputationScore;
    private final int behaviorScore;
    private final boolean signedFile;
    private final boolean macroEnabled;
    private final int networkIndicators;

    public SampleSubmission(
            String sampleName,
            String sourceTeam,
            String fileType,
            int reputationScore,
            int behaviorScore,
            boolean signedFile,
            boolean macroEnabled,
            int networkIndicators
    ) {
        this.sampleName = sampleName;
        this.sourceTeam = sourceTeam;
        this.fileType = fileType;
        this.reputationScore = reputationScore;
        this.behaviorScore = behaviorScore;
        this.signedFile = signedFile;
        this.macroEnabled = macroEnabled;
        this.networkIndicators = networkIndicators;
    }

    public String getSampleName() {
        return sampleName;
    }

    public String getSourceTeam() {
        return sourceTeam;
    }

    public String getFileType() {
        return fileType;
    }

    public int getReputationScore() {
        return reputationScore;
    }

    public int getBehaviorScore() {
        return behaviorScore;
    }

    public boolean isSignedFile() {
        return signedFile;
    }

    public boolean isMacroEnabled() {
        return macroEnabled;
    }

    public int getNetworkIndicators() {
        return networkIndicators;
    }
}
