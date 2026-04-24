# Security Sample Triage Console

## Overview

Security Sample Triage Console is a Java-based internal security utility for reviewing submitted files and assigning a practical triage disposition based on lightweight risk signals.

This project is positioned as a recruiter-ready backend and security portfolio piece. It upgrades a rough malware-sandbox integration concept into a cleaner and more practical internal review workflow that better matches how teams triage suspicious samples before deeper investigation.

## Real-World Business Use Case

This project maps to practical workflows used by:

- Security Operations Teams
- Threat Triage Analysts
- Internal Review Queues
- Security Engineering Teams
- Technical Portfolio Demonstrations

A team may need to answer questions such as:

- Which submitted files should go straight to a sandbox queue?
- Which files deserve manual analyst review first?
- Which files can be archived for passive monitoring?
- How can a simple internal review client summarize why a submission was flagged?

This tool is useful for triage demos, internal review prototypes, and portfolio presentation of security-oriented Java applications.

## Key Features

- Sample Review Queue
- Rule-Based Triage Logic
- Escalate, Review, Or Archive Dispositions
- Per-Sample Recommendation Output
- Severity Summary Reporting
- Maven Project Structure

## Tech Stack

- Java 17
- Maven

## Repository Contents

- `pom.xml`
- `src/main/java/com/security/triage/Main.java`
- `src/main/java/com/security/triage/SampleSubmission.java`
- `src/main/java/com/security/triage/ReviewResult.java`
- `src/main/java/com/security/triage/ThreatReviewEngine.java`
- `README.md`

## How To Run

### Build

```powershell
mvn clean package


