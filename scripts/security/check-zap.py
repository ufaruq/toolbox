"""Fail on medium/high passive alerts or a scan that did not reach the fixture."""
import json
import sys
from pathlib import Path

report = json.loads(Path(sys.argv[1]).read_text())
sites = report.get("site", [])
if not sites or not any(site.get("@name") == "http://127.0.0.1:18089" for site in sites):
    raise SystemExit("ZAP report has no expected fixture site")
findings = [alert for site in sites for alert in site.get("alerts", [])
            if int(alert["riskcode"]) >= 2]
for alert in findings:
    print(f"ZAP {alert['pluginid']}: {alert['name']} (risk {alert['riskcode']})")
print(f"ZAP medium/high findings: {len(findings)}")
raise SystemExit(1 if findings else 0)
