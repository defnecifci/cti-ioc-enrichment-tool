def calculate_risk_score(
    vt_result: dict,
    ioc: str,
    abuse_result: dict = None,
    urlscan_result: dict = None
) -> dict:
    score = 0
    reasons = []

    malicious = vt_result.get("malicious", 0)
    suspicious = vt_result.get("suspicious", 0)

    if malicious > 0:
        score += 50
        reasons.append(f"VirusTotal malicious detections: {malicious}")

    if suspicious > 0:
        score += 25
        reasons.append(f"VirusTotal suspicious detections: {suspicious}")

    if abuse_result and not abuse_result.get("error"):
        abuse_score = abuse_result.get("abuse_confidence_score", 0)
        total_reports = abuse_result.get("total_reports", 0)

        if abuse_score >= 75:
            score += 40
            reasons.append(f"AbuseIPDB high abuse confidence score: {abuse_score}")

        elif abuse_score >= 25:
            score += 20
            reasons.append(f"AbuseIPDB medium abuse confidence score: {abuse_score}")

        if total_reports >= 100:
            score += 10
            reasons.append(f"AbuseIPDB total reports: {total_reports}")

    if urlscan_result and not urlscan_result.get("error"):
        total_results = urlscan_result.get("total_results", 0)

    if total_results > 0:
        reasons.append(f"urlscan historical results found: {total_results}")

    phishing_keywords = [
        "login",
        "verify",
        "secure",
        "account",
        "bank",
        "update",
        "password"
    ]

    for keyword in phishing_keywords:
        if keyword in ioc.lower():
            score += 10
            reasons.append(f"Phishing-related keyword found: {keyword}")
            break

    if score >= 70:
        risk_level = "HIGH"
    elif score >= 30:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    if not reasons:
        reasons.append("No significant malicious or suspicious indicators were found.")

    return {
        "score": min(score, 100),
        "risk_level": risk_level,
        "reasons": reasons
    }