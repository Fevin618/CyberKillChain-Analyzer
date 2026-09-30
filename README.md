# CyberKillChain-Analyzer

A cybersecurity incident analysis platform that analyzes security events, maps them to the Cyber Kill Chain and MITRE ATT&CK framework, correlates related events, calculates risk, and generates incident insights.

## Features

- Security event ingestion from CSV and JSON
- Rule-based threat detection
- Cyber Kill Chain stage classification
- MITRE ATT&CK technique mapping
- Event correlation
- Incident detection and grouping
- Risk scoring
- Attack timeline visualization
- Attack path / relationship visualization
- Indicators of Compromise (IoCs) extraction
- Incident investigation details
- Security recommendations
- Synthetic security event dataset
- REST API
- Automated testing

## Attack Analysis

The analyzer uses the following Cyber Kill Chain stages:

1. Reconnaissance
2. Weaponization
3. Delivery
4. Exploitation
5. Installation
6. Command and Control
7. Actions on Objectives

Detected events are correlated to identify possible multi-stage attack activity.

## MITRE ATT&CK

The project maps detected activities to relevant MITRE ATT&CK techniques.

Examples include:

- T1566.001 - Spearphishing Attachment
- T1059.001 - PowerShell
- T1078 - Valid Accounts
- T1046 - Network Service Scanning
- T1105 - Ingress Tool Transfer
- T1071.001 - Web Protocols
- T1071.004 - DNS
- T1041 - Exfiltration Over C2 Channel

## Detection Workflow

```text
Security Events
       |
       v
Event Parsing
       |
       v
Detection Rules
       |
       v
Event Correlation
       |
       v
Kill Chain Mapping
       |
       v
MITRE ATT&CK Mapping
       |
       v
Risk Scoring
       |
       v
Incident Analysis
       |
       v
Investigation Report




##Example Attack Flow
Failed Login
      |
      v
Successful Login
      |
      v
PowerShell Execution
      |
      v
Malicious File Download
      |
      v
Command & Control
      |
      v
Data Exfiltration

##Project Structure

CyberKillChain-Analyzer/
│
├── backend/
│   ├── app/
│   ├── tests/
│   └── requirements.txt
│
├── frontend/
│   ├── src/
│   ├── public/
│   └── package.json
│
├── data/
│   ├── sample_events.csv
│   ├── sample_events.json
│   └── mitre_techniques.json
│
├── docs/
│
├── .gitignore
├── .env.example
├── README.md
└── LICENSE
