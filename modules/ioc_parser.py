import re
from urllib.parse import urlparse


def detect_ioc_type(ioc: str) -> str:
    ioc = ioc.strip()

    ip_pattern = r"^(?:\d{1,3}\.){3}\d{1,3}$"

    if re.match(ip_pattern, ioc):
        return "ip"

    if ioc.startswith("http://") or ioc.startswith("https://"):
        return "url"

    return "domain"


def normalize_ioc(ioc: str) -> str:
    ioc = ioc.strip()

    if detect_ioc_type(ioc) == "url":
        parsed = urlparse(ioc)
        return parsed.netloc

    return ioc