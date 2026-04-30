from datetime import datetime
import os


def generate_report(
    original_ioc,
    normalized_ioc,
    ioc_type,
    vt_result,
    risk_result,
    mitre_result,
    abuse_result=None,
    urlscan_result=None
):
    os.makedirs("reports", exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_ioc = normalized_ioc.replace("/", "_").replace(":", "_")
    filename = f"reports/report_{safe_ioc}_{timestamp}.txt"

    recommendations = [
        "Block the IOC on proxy/firewall if confirmed malicious.",
        "Monitor DNS, proxy, and endpoint logs for related activity.",
        "Search SIEM logs for access attempts to the IOC.",
        "Educate users about suspicious login or account verification pages."
    ]

    report = f"""
Threat Intelligence Report

Target: {normalized_ioc}
Original IOC: {original_ioc}
IOC Type: {ioc_type}
Report Time: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

VirusTotal Summary:
- Malicious: {vt_result.get("malicious", 0)}
- Suspicious: {vt_result.get("suspicious", 0)}
- Harmless: {vt_result.get("harmless", 0)}
- Undetected: {vt_result.get("undetected", 0)}
"""

    if abuse_result and not abuse_result.get("error"):
        report += f"""
AbuseIPDB Summary:
- Abuse Confidence Score: {abuse_result.get("abuse_confidence_score", 0)}
- Total Reports: {abuse_result.get("total_reports", 0)}
- Country Code: {abuse_result.get("country_code")}
- ISP: {abuse_result.get("isp")}
- Domain: {abuse_result.get("domain")}
"""

    if urlscan_result and not urlscan_result.get("error"):
        report += f"""
URLScan Summary:
- Historical Results: {urlscan_result.get("total_results", 0)}
"""

    report += f"""
Risk Assessment:
- Risk Level: {risk_result["risk_level"]}
- Risk Score: {risk_result["score"]}/100

Findings:
"""

    for reason in risk_result["reasons"]:
        report += f"- {reason}\n"

    report += "\nMITRE ATT&CK Mapping:\n"
    for technique in mitre_result:
        report += f"- {technique['id']} - {technique['name']}: {technique['reason']}\n"

    report += "\nRecommendations:\n"
    for recommendation in recommendations:
        report += f"- {recommendation}\n"

    with open(filename, "w", encoding="utf-8") as file:
        file.write(report.strip() + "\n")

    return filename