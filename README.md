# SentinelQueue Threat Sample Intake And Triage Console

## Overview

SentinelQueue is a simulated internal SOC intake and triage console for reviewing suspicious sample metadata, scoring risk, and routing submissions to the right analyst workflow.

This project upgrades the original `Security-Sample-Triage-Console` into a more complete cloud-and-security portfolio system with a Java triage engine and a polished SOC-style frontend dashboard.

The project is intentionally safe: it does not execute files, unpack samples, or perform real malware analysis. It uses simulated metadata and indicators to demonstrate how a security operations team could structure intake review decisions.

## Real-World Relevance

Security teams often need to quickly decide whether a suspicious file submission should be escalated, manually reviewed, monitored, or archived. SentinelQueue models that decision process with:

- Metadata-Based Sample Intake
- Rule-Based Triage Scoring
- Analyst Queue Routing
- Evidence Indicator Cards
- Chain-Of-Custody Timeline
- Executive SOC Summary
- Premium Dashboard For Portfolio Presentation

## Cloud + AI Direction

SentinelQueue is designed to connect naturally to future cloud and AI workflows:

- Cloud Storage Intake Queues
- Serverless Triage Workers
- SIEM/SOAR Case Creation
- Sandbox API Routing
- AI-Assisted Analyst Summaries
- Evidence And Chain-Of-Custody Reporting
- Threat Intelligence Enrichment

This version is a safe portfolio simulation and does not claim production deployment.

## Tech Stack

- Java 17
- Maven
- HTML
- CSS
- JavaScript

## Project Structure

```text
pom.xml
src/main/java/com/security/triage/Main.java
src/main/java/com/security/triage/SampleSubmission.java
src/main/java/com/security/triage/ReviewResult.java
src/main/java/com/security/triage/ThreatReviewEngine.java
dashboard/index.html
dashboard/styles.css
dashboard/app.js
screenshots/
README.md
