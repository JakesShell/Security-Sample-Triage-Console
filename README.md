# SentinelQueue Threat Sample Intake And Triage Console

## Overview

SentinelQueue is a simulated internal SOC intake and triage console for reviewing suspicious sample metadata, scoring risk, and routing submissions to the right analyst workflow.

This project upgrades the original `SentinelQueue-Threat-Sample-Intake-And-Triage-Console` into a more complete cloud-and-security portfolio system with a Java triage engine and a polished SOC-style frontend dashboard.

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

## Project Summary

SentinelQueue is an enterprise-style SOC workflow demo for threat sample intake, safe static file scanning, analyst triage, evidence tracking, and simulated sandbox routing.

## What It Does

- Uploads a real local file through the browser
- Reads safe file details without executing the file
- Detects file name, type, size, browser MIME type, SHA-256 hash, magic bytes, first-seen time, and last modified date
- Scores the file using static risk indicators
- Routes higher-risk files into a simulated sandbox queue
- Shows analyst workflow pages for Intake, Analysis, Sandbox, Evidence, Reports, and Config
- Preserves a safe demo boundary by never executing, unpacking, detonating, or opening suspicious files

## Cloud And AI Direction

This project supports the larger Cloud + AI operations portfolio direction by modeling how a cloud security team could route suspicious files into controlled analysis workflows, preserve evidence, and prepare future AI-assisted triage recommendations.

## Safe Demo Boundary

This portfolio version performs browser-side static file inspection only. It does not execute uploaded files, open macros, unpack suspicious archives, or detonate malware.