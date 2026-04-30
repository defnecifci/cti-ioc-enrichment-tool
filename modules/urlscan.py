import requests

BASE_URL = "https://urlscan.io/api/v1/search/"


def analyze_urlscan(query: str) -> dict:
    params = {
        "q": query
    }

    try:
        response = requests.get(BASE_URL, params=params, timeout=15)

        if response.status_code != 200:
            return {
                "source": "urlscan",
                "ioc": query,
                "error": True
            }

        data = response.json()

        total = data.get("total", 0)

        return {
            "source": "urlscan",
            "ioc": query,
            "type": "domain/url",
            "total_results": total,
            "error": False
        }

    except Exception as e:
        return {
            "source": "urlscan",
            "ioc": query,
            "error": True,
            "message": str(e)
        }