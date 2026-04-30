🛡️ Automated Threat Intelligence Enrichment & Phishing Detection Tool
📌 Project Overview

This project is a Python-based Cyber Threat Intelligence (CTI) automation tool designed to analyze suspicious Indicators of Compromise (IOCs) such as domains, URLs, and IP addresses.

The tool enriches IOCs using open-source threat intelligence APIs, calculates a risk score, maps findings to MITRE ATT&CK techniques, and generates structured threat intelligence reports.

🎯 Purpose
Automate IOC analysis
Reduce manual investigation effort
Provide actionable threat intelligence
⚙️ Features
IOC type detection (Domain / URL / IP)
IOC normalization
VirusTotal integration
AbuseIPDB integration
URLScan integration
Risk scoring system
MITRE ATT&CK mapping
TXT report generation
Batch IOC analysis
JSON and CSV export
🧰 Technologies
Python
REST APIs
VirusTotal API
AbuseIPDB API
URLScan API
MITRE ATT&CK
📂 Project Structure
cti-ioc-enrichment-tool/
├── main.py
├── config.py
├── requirements.txt
├── sample_iocs.txt
├── README.md
├── modules/
│   ├── ioc_parser.py
│   ├── virustotal.py
│   ├── abuseipdb.py
│   ├── urlscan.py
│   ├── risk_score.py
│   ├── mitre_mapper.py
│   ├── report_generator.py
│   └── summary_exporter.py
└── reports/
🚀 How to Run

Install dependencies:

pip install -r requirements.txt

Create .env file:

VIRUSTOTAL_API_KEY=your_api_key
ABUSEIPDB_API_KEY=your_api_key

Run the tool:

python main.py
📊 Example Use Cases
IOC enrichment
Phishing detection
Threat intelligence automation
SOC analysis support
🏁 Outcome

This project demonstrates practical skills in:

Cyber Threat Intelligence (CTI)
OSINT
Python automation
API integration
Risk-based analysis
