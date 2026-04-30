import requests
from config import VIRUSTOTAL_API_KEY


BASE_URL = "https://www.virustotal.com/api/v3"


def get_headers():
    return {
        "x-apikey": VIRUSTOTAL_API_KEY
    }


def analyze_domain(domain: str) -> dict:
    url = f"{BASE_URL}/domains/{domain}"

    response = requests.get(url, headers=get_headers(), timeout=15)

    if response.status_code != 200:
        return {
            "source": "VirusTotal",
            "error": True,
            "status_code": response.status_code,
            "message": response.text
        }

    data = response.json()

    stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})

    return {
        "source": "VirusTotal",
        "ioc": domain,
        "type": "domain",
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
        "error": False
    }


def analyze_ip(ip: str) -> dict:
    url = f"{BASE_URL}/ip_addresses/{ip}"

    response = requests.get(url, headers=get_headers(), timeout=15)

    if response.status_code != 200:
        return {
            "source": "VirusTotal",
            "error": True,
            "status_code": response.status_code,
            "message": response.text
        }

    data = response.json()

    stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})

    return {
        "source": "VirusTotal",
        "ioc": ip,
        "type": "ip",
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
        "error": False
    }