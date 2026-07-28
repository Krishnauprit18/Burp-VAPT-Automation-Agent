import json
import os
import time
from pathlib import Path

import requests
import urllib3

SEED_URLS = os.environ.get("SCAN_SEED_URLS", os.environ.get("OFBIZ_URL", "")).strip()
BRIDGE = os.environ["BURP_BRIDGE_URL"].rstrip("/")
HEAD = {"Authorization": "Bearer " + os.environ["BURP_BRIDGE_TOKEN"]}
HOST = os.environ.get("TARGET_HOST", "ofbiz").strip()
ART = Path(os.environ.get("ARTIFACTS_DIR", "/artifacts"))
POLL_SECONDS = int(os.environ.get("SCAN_POLL_SECONDS", "15"))
MAX_SCAN_SECONDS = int(os.environ.get("MAX_SCAN_SECONDS", "18000"))
ART.mkdir(parents=True, exist_ok=True)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def seed_urls():
    urls = [url.strip() for url in SEED_URLS.split(",") if url.strip()]
    if not urls:
        raise RuntimeError("SCAN_SEED_URLS (or OFBIZ_URL) must contain at least one URL")
    return urls


def wait_target():
    urls = seed_urls()
    print(f"[*] Waiting for target: {urls[0]}")
    deadline = time.monotonic() + 300
    while time.monotonic() < deadline:
        try:
            response = requests.get(urls[0], timeout=10, verify=False, allow_redirects=False)
            if response.status_code < 500:
                print(f"[✓] Target ready: HTTP {response.status_code}")
                return
        except requests.RequestException:
            pass
        time.sleep(5)
    raise RuntimeError("Target not ready after 5 minutes")


def wait_health():
    print("[*] Waiting for Burp Bridge...")
    for _ in range(120):
        try:
            r = requests.get(BRIDGE + "/health", headers=HEAD, timeout=3)
            if r.ok:
                print(f"[✓] Bridge ready: {r.json()}")
                return
        except requests.RequestException:
            pass
        time.sleep(2)
    raise RuntimeError("Burp Bridge not ready after 4 minutes")

def start_scan():
    print(f"[*] Starting Burp crawl → active audit on {SEED_URLS} ...")
    r = requests.post(
        BRIDGE + "/scan/start",
        headers=HEAD,
        params={"url": SEED_URLS, "host": HOST},
        timeout=30
    )
    r.raise_for_status()
    data = r.json()
    print(f"[✓] Scan started: {data}")
    return data["scanId"]

def poll_status(scan_id):
    print("[*] Polling scan status (crawl → audit → complete)...")
    fail_count = 0
    started = time.monotonic()
    while True:
        if time.monotonic() - started > MAX_SCAN_SECONDS:
            raise RuntimeError(f"Scan exceeded MAX_SCAN_SECONDS={MAX_SCAN_SECONDS}")
        try:
            s = requests.get(BRIDGE + f"/scan/status?id={scan_id}", headers=HEAD, timeout=30)
            s.raise_for_status()
            data = s.json()
            fail_count = 0  # reset on success
            (ART / "scan-status.json").write_text(json.dumps(data, indent=2))
            print(f"    {data}", flush=True)
            if data.get("error"):
                raise RuntimeError(f"Scan error: {data['error']}")
            if data.get("complete"):
                return data
        except requests.RequestException as e:
            fail_count += 1
            print(f"    [!] Poll failed ({fail_count}/5): {e}", flush=True)
            if fail_count >= 5:
                raise RuntimeError(f"Bridge unreachable after 5 retries: {e}")
            time.sleep(5)
            continue
        time.sleep(POLL_SECONDS)

def get_report(scan_id):
    print("[*] Generating report...")
    r = requests.post(BRIDGE + f"/scan/report?id={scan_id}", headers=HEAD, timeout=120)
    r.raise_for_status()
    data = r.json()
    (ART / "run-summary.json").write_text(json.dumps({"scanId": scan_id, "report": data}, indent=2))
    print(f"[✓] Report saved: {data['path']}  |  Issues: {data['issues']}")
    return data

def main():
    wait_target()
    wait_health()
    scan_id = start_scan()
    poll_status(scan_id)
    report = get_report(scan_id)
    print(f"\n[✓] DONE — Issues found: {report['issues']}")
    print(f"    Report: {report['path']}")

if __name__ == "__main__":
    main()
