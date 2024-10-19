# Malware Analysis Sandbox

## Overview

The **Malware Analysis Sandbox** project is a Java application designed to automate the process of malware analysis using the Cuckoo Sandbox. This tool allows security researchers and professionals to submit malware samples for automated analysis and retrieve detailed reports on their behavior, facilitating a deeper understanding of potential threats.

## Key Features

- **Automated Sample Submission**: Easily submit malware samples to Cuckoo Sandbox for analysis.
- **Analysis Reporting**: Retrieve and display detailed analysis reports, including behavioral data and indicators of compromise.
- **Configuration Management**: Use a properties file for easy configuration of API settings.

## Technologies Used

- **Java**: The primary programming language used for developing the application.
- **Apache HttpClient**: For making HTTP requests to the Cuckoo Sandbox API.
- **Jackson**: For handling JSON data and parsing responses.
