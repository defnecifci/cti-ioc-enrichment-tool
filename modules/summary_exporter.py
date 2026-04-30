import csv
import json
import os
from datetime import datetime


def export_summary(results: list) -> dict:
    os.makedirs("reports", exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    json_path = f"reports/summary_{timestamp}.json"
    csv_path = f"reports/summary_{timestamp}.csv"

    with open(json_path, "w", encoding="utf-8") as json_file:
        json.dump(results, json_file, indent=4, ensure_ascii=False)

    with open(csv_path, "w", encoding="utf-8", newline="") as csv_file:
        fieldnames = ["ioc", "type", "risk_level", "risk_score", "report_path"]
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)

        writer.writeheader()
        writer.writerows(results)

    return {
        "json_path": json_path,
        "csv_path": csv_path
    }