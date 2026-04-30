def map_to_mitre(ioc: str, risk_result: dict) -> list:
    techniques = []

    phishing_keywords = ["login", "verify", "secure", "account", "bank", "update", "password"]

    if any(keyword in ioc.lower() for keyword in phishing_keywords):
        techniques.append({
            "id": "T1566",
            "name": "Phishing",
            "reason": "IOC contains phishing-related keywords."
        })

        techniques.append({
            "id": "T1204",
            "name": "User Execution",
            "reason": "User interaction may be required to access the malicious link."
        })

    if risk_result.get("score", 0) >= 70:
        techniques.append({
            "id": "T1583",
            "name": "Acquire Infrastructure",
            "reason": "High-risk IOC may indicate attacker-controlled infrastructure."
        })

    if not techniques:
        techniques.append({
            "id": "N/A",
            "name": "No direct mapping",
            "reason": "No clear MITRE ATT&CK technique identified from available indicators."
        })

    return techniques