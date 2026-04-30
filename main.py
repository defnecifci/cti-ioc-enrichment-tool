from modules.ioc_parser import detect_ioc_type, normalize_ioc
from modules.virustotal import analyze_domain, analyze_ip
from modules.risk_score import calculate_risk_score
from modules.mitre_mapper import map_to_mitre
from modules.report_generator import generate_report
from modules.abuseipdb import analyze_ip_abuseipdb
from modules.summary_exporter import export_summary
from modules.urlscan import analyze_urlscan


def analyze_single_ioc(ioc):
    ioc_type = detect_ioc_type(ioc)
    normalized_ioc = normalize_ioc(ioc)

    print("\n==============================")
    print("--- IOC Analysis Started ---")
    print(f"Original IOC: {ioc}")
    print(f"Normalized IOC: {normalized_ioc}")
    print(f"IOC Type: {ioc_type}")

    abuse_result = None

    if ioc_type == "ip":
        vt_result = analyze_ip(normalized_ioc)
        abuse_result = analyze_ip_abuseipdb(normalized_ioc)
    else:
        vt_result = analyze_domain(normalized_ioc)

    print("\n--- VirusTotal Result ---")
    print(vt_result)

    urlscan_result = analyze_urlscan(normalized_ioc)

    print("\n--- URLScan Result ---")
    print(f"URLScan Results: {urlscan_result.get('total_results', 0)}")

    if abuse_result:
        print("\n--- AbuseIPDB Result ---")
        print(abuse_result)

    risk_result = calculate_risk_score(
    vt_result,
    normalized_ioc,
    abuse_result,
    urlscan_result
)

    print("\n--- Risk Score ---")
    print(f"Risk Level: {risk_result['risk_level']}")
    print(f"Risk Score: {risk_result['score']}/100")

    print("\nReasons:")
    for reason in risk_result["reasons"]:
        print(f"- {reason}")

    mitre_result = map_to_mitre(normalized_ioc, risk_result)

    print("\n--- MITRE ATT&CK Mapping ---")
    for technique in mitre_result:
        print(f"- {technique['id']} - {technique['name']}: {technique['reason']}")

    report_path = generate_report(
    original_ioc=ioc,
    normalized_ioc=normalized_ioc,
    ioc_type=ioc_type,
    vt_result=vt_result,
    risk_result=risk_result,
    mitre_result=mitre_result,
    abuse_result=abuse_result,
    urlscan_result=urlscan_result
)

    print(f"\nReport generated: {report_path}")
    print("--- Analysis Finished ---")

    return {
        "ioc": normalized_ioc,
        "type": ioc_type,
        "risk_level": risk_result["risk_level"],
        "risk_score": risk_result["score"],
        "report_path": report_path
    }


def analyze_from_file(filename):
    with open(filename, "r", encoding="utf-8") as file:
        iocs = [line.strip() for line in file if line.strip()]

    results = []

    for ioc in iocs:
        result = analyze_single_ioc(ioc)
        results.append(result)

    return results


def main():
    print("1 - Analyze single IOC")
    print("2 - Analyze IOC list from sample_iocs.txt")

    choice = input("Choose option: ")

    if choice == "1":
        ioc = input("Analyze IOC: ")
        analyze_single_ioc(ioc)

    elif choice == "2":
        results = analyze_from_file("sample_iocs.txt")

        print("\n====== Summary ======")
        for result in results:
            print(
                f"{result['ioc']} | {result['type']} | "
                f"{result['risk_level']} | {result['risk_score']}/100"
            )

        export_paths = export_summary(results)

        print("\nSummary files generated:")
        print(f"- JSON: {export_paths['json_path']}")
        print(f"- CSV: {export_paths['csv_path']}")

    else:
        print("Invalid option.")


if __name__ == "__main__":
    main()