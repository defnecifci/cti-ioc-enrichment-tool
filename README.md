# Automated Threat Intelligence Enrichment & Phishing Detection Tool
##  Project Overview

This project is a Python-based Cyber Threat Intelligence (CTI) automation tool designed to analyze suspicious Indicators of Compromise (IOCs) such as domains, URLs, and IP addresses.

The tool enriches IOCs using open-source threat intelligence APIs, calculates a risk score, maps findings to MITRE ATT&CK techniques, and generates structured threat intelligence reports.

##  Purpose
The purpose of this project is to automate IOC analysis and reduce manual effort for security analysts by:
Enriching IOCs with threat intelligence data
Identifying malicious or suspicious indicators
Generating actionable CTI reports

##  Features
IOC type detection (Domain / URL / IP)
IOC normalization
VirusTotal integration
AbuseIPDB integration (IP reputation)
Risk scoring system
MITRE ATT&CK mapping
TXT report generation
Batch IOC analysis from file
JSON and CSV summary export

##  Technologies Used
Python
REST APIs
VirusTotal API
AbuseIPDB API
MITRE ATT&CK Framework
OSINT techniques

##  Project Structure
```txt
cti-ioc-enrichment-tool/
│
├── main.py
├── config.py
├── requirements.txt
├── sample_iocs.txt
├── README.md
│
├── modules/
│   ├── ioc_parser.py
│   ├── virustotal.py
│   ├── abuseipdb.py
│   ├── risk_score.py
│   ├── mitre_mapper.py
│   ├── report_generator.py
│   └── summary_exporter.py
│
└── reports/
    ├── report_*.txt
    ├── summary_*.json
    └── summary_*.csv
```

##  How It Works
User inputs a single IOC or a list of IOCs
Tool detects IOC type (domain, URL, IP)
IOC is normalized
VirusTotal is queried for reputation data
AbuseIPDB is queried for IP reputation
Risk score is calculated
Findings are mapped to MITRE ATT&CK techniques
A structured report is generated

##  Example Output
Threat Intelligence Report

Target: secure-login-update.com
IOC Type: domain

## VirusTotal Summary:
- Malicious: 12
- Suspicious: 0
- Harmless: 45
- Undetected: 34

## Risk Assessment:
- Risk Level: MEDIUM
- Risk Score: 60/100

## Findings:
- VirusTotal malicious detections: 12
- Phishing-related keyword found: login

## MITRE ATT&CK Mapping:
- T1566 - Phishing
- T1204 - User Execution

## Recommendations:
- Block the IOC on proxy/firewall
- Monitor logs
- Investigate user activity

##  Risk Scoring Logic
Indicator	Score
VirusTotal malicious detection	+50
VirusTotal suspicious detection	+25
AbuseIPDB high confidence score	+40
AbuseIPDB medium confidence score	+20
AbuseIPDB high report count	+10
Phishing-related keyword	+10

## Risk Levels
0 - 29   → LOW
30 - 69  → MEDIUM
70 - 100 → HIGH

##  MITRE ATT&CK Mapping
Condition	Technique
Phishing keywords in IOC	T1566 - Phishing
Suspicious user interaction	T1204 - User Execution
High-risk infrastructure	T1583 - Acquire Infrastructure

##  How to Run
Install dependencies
pip install -r requirements.txt
Create .env file
VIRUSTOTAL_API_KEY=your_api_key
ABUSEIPDB_API_KEY=your_api_key
Run the tool
python main.py

##  Use Cases
IOC enrichment
Phishing detection
IP reputation analysis
CTI reporting
SOC analyst triage support
Threat intelligence automation

##  Outcome

This project demonstrates:

Cyber Threat Intelligence skills
OSINT usage
Python automation
API integration
Risk-based analysis
MITRE ATT&CK knowledge
Report generation for security teams

## Sample IOC File

A sample IOC file (`sample_iocs.txt`) is included for testing purposes.  
You can modify this file to analyze your own domains, URLs, or IP addresses.
