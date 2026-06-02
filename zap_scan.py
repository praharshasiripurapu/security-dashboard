"""
zap_scan.py — OWASP ZAP automation script for SecurityDash
Runs a ZAP scan against the FastAPI app and sends results to /ingest-zap

Prerequisites:
    - OWASP ZAP running with API enabled (default: http://localhost:8080)
    - pip install python-owasp-zap-v2.4 httpx

Usage:
    python zap_scan.py                        # scan localhost:8000
    python zap_scan.py --target http://...    # custom target
    python zap_scan.py --zap-url http://...   # custom ZAP API URL
    python zap_scan.py --report               # save JSON report too
"""

import time
import json
import httpx
import argparse
from datetime import datetime
from pathlib import Path

try:
    from zapv2 import ZAPv2
    ZAP_AVAILABLE = True
except ImportError:
    ZAP_AVAILABLE = False
    print("[zap] WARNING: python-owasp-zap-v2.4 not installed.")
    print("[zap] Run: pip install python-owasp-zap-v2.4")
    print("[zap] Falling back to mock scan mode.\n")


def mock_scan_results():
    """Returns realistic mock ZAP findings for testing the pipeline without ZAP installed."""
    return {
        "site": [
            {
                "name": "http://localhost:8000",
                "alerts": [
                    {
                        "name": "Missing Anti-clickjacking Header",
                        "riskdesc": "Medium (Medium)",
                        "description": "The response does not include the X-Frame-Options header.",
                        "solution": "Add X-Frame-Options header."
                    },
                    {
                        "name": "X-Content-Type-Options Header Missing",
                        "riskdesc": "Low (Medium)",
                        "description": "The X-Content-Type-Options header is not set.",
                        "solution": "Ensure X-Content-Type-Options: nosniff is set."
                    },
                    {
                        "name": "Server Leaks Version Information",
                        "riskdesc": "Low (Medium)",
                        "description": "The web/application server is leaking version info.",
                        "solution": "Remove or obfuscate server version headers."
                    },
                    {
                        "name": "SQL Injection (Blind)",
                        "riskdesc": "High (High)",
                        "description": "Blind SQL injection detected in login parameter.",
                        "solution": "Use parameterized queries."
                    },
                    {
                        "name": "Cross-Site Scripting (Reflected)",
                        "riskdesc": "Medium (High)",
                        "description": "Reflected XSS in username parameter.",
                        "solution": "Validate and escape user input."
                    }
                ]
            }
        ]
    }


def run_zap_scan(target: str, zap_url: str, api_key: str = "changeme") -> dict:
    """Run a full ZAP spider + active scan and return the results dict."""
    if not ZAP_AVAILABLE:
        print("[zap] Using mock scan results (ZAP not installed)")
        time.sleep(2)  # simulate scan time
        return mock_scan_results()

    zap = ZAPv2(apikey=api_key, proxies={"http": zap_url, "https": zap_url})

    print(f"[zap] Accessing target: {target}")
    zap.urlopen(target)
    time.sleep(2)

    # Spider
    print("[zap] Starting spider...")
    spider_id = zap.spider.scan(target)
    while int(zap.spider.status(spider_id)) < 100:
        pct = zap.spider.status(spider_id)
        print(f"[zap]   Spider progress: {pct}%", end="\r")
        time.sleep(2)
    print("\n[zap] Spider complete.")

    # Active scan
    print("[zap] Starting active scan...")
    scan_id = zap.ascan.scan(target)
    while int(zap.ascan.status(scan_id)) < 100:
        pct = zap.ascan.status(scan_id)
        print(f"[zap]   Active scan progress: {pct}%", end="\r")
        time.sleep(5)
    print("\n[zap] Active scan complete.")

    # Get alerts
    alerts = zap.core.alerts(baseurl=target)
    return {
        "site": [
            {
                "name": target,
                "alerts": [
                    {
                        "name": a.get("alert"),
                        "riskdesc": f"{a.get('risk')} ({a.get('confidence')})",
                        "description": a.get("description"),
                        "solution": a.get("solution"),
                        "url": a.get("url")
                    }
                    for a in alerts
                ]
            }
        ]
    }


def ingest_results(results: dict, dashboard_url: str) -> dict:
    """POST the ZAP results to the FastAPI /ingest-zap endpoint."""
    with httpx.Client() as client:
        resp = client.post(
            f"{dashboard_url}/ingest-zap",
            json=results,
            timeout=10
        )
        resp.raise_for_status()
        return resp.json()


def save_report(results: dict, output_dir: str = "zap/reports"):
    """Save the ZAP results as a timestamped JSON file."""
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = Path(output_dir) / f"zap_report_{ts}.json"
    with open(path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"[zap] Report saved to {path}")
    return str(path)


def print_summary(ingest_response: dict):
    counts = ingest_response.get("counts", {})
    print("\n" + "="*40)
    print("  ZAP Scan Summary")
    print("="*40)
    print(f"  🔴 HIGH:   {counts.get('high', 0)}")
    print(f"  🟠 MEDIUM: {counts.get('medium', 0)}")
    print(f"  🟡 LOW:    {counts.get('low', 0)}")
    print(f"  ℹ️  INFO:   {counts.get('informational', 0)}")
    print("="*40)
    print("  Results pushed to Prometheus via /ingest-zap")
    print("  Check Grafana Panel 5 for visualization.\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ZAP scan runner for SecurityDash")
    parser.add_argument("--target",       default="http://localhost:8000", help="Target URL to scan")
    parser.add_argument("--zap-url",      default="http://localhost:8080",  help="ZAP API URL")
    parser.add_argument("--dashboard-url",default="http://localhost:8000",  help="SecurityDash FastAPI URL")
    parser.add_argument("--api-key",      default="changeme",               help="ZAP API key")
    parser.add_argument("--report",       action="store_true",               help="Save JSON report to disk")
    args = parser.parse_args()

    print(f"[zap] Starting scan of {args.target}")
    results = run_zap_scan(args.target, args.zap_url, args.api_key)

    if args.report:
        save_report(results)

    print("[zap] Sending results to dashboard...")
    response = ingest_results(results, args.dashboard_url)
    print_summary(response)
