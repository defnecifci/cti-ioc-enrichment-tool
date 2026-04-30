import requests
from config import ABUSEIPDB_API_KEY


BASE_URL = "https://api.abuseipdb.com/api/v2/check"


def analyze_ip_abuseipdb(ip: str) -> dict:
    headers = {
        "Accept": "application/json",
        "Key": ABUSEIPDB_API_KEY
    }

    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90
    }

    try:
        response = requests.get(
            BASE_URL,
            headers=headers,
            params=params,
            timeout=15
        )

        if response.status_code != 200:
            return {
                "source": "AbuseIPDB",
                "ioc": ip,
                "error": True,
                "status_code": response.status_code,
                "message": response.text
            }

        data = response.json().get("data", {})

        return {
            "source": "AbuseIPDB",
            "ioc": ip,
            "type": "ip",
            "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
            "country_code": data.get("countryCode"),
            "isp": data.get("isp"),
            "domain": data.get("domain"),
            "total_reports": data.get("totalReports", 0),
            "error": False
        }

    except requests.RequestException as e:
        return {
            "source": "AbuseIPDB",
            "ioc": ip,
            "error": True,
            "message": str(e)
        }