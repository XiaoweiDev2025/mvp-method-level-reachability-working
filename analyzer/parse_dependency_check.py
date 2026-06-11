import json
from pathlib import Path

REPORT_PATH = Path("reports/dependency-check/dependency-check-report.json")

def main():
    with open(REPORT_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)

    dependencies = data.get("dependencies", [])

    for dep in dependencies:
        file_name = dep.get("fileName")
        vulnerabilities = dep.get("vulnerabilities", [])

        if vulnerabilities:
            print(f"\nDependency:{file_name}")
            for vuln in vulnerabilities:
                cve = vuln.get("name")
                severity = vuln.get("severity")
                cvss = vuln.get("cvssv3", {}).get("baseScore")
                print(f"  - {cve} | Severity: {severity} | CVSS: {cvss}")

if __name__ == "__main__":
    main() 