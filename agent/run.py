import json, os, time
from pathlib import Path
import requests

URL    = os.environ["OFBIZ_URL"]
BRIDGE = os.environ["BURP_BRIDGE_URL"]
HEAD   = {"Authorization": "Bearer " + os.environ["BURP_BRIDGE_TOKEN"]}
HOST   = os.environ.get("TARGET_HOST", "ofbiz")
ART    = Path(os.environ.get("ARTIFACTS_DIR", "/artifacts"))
ART.mkdir(parents=True, exist_ok=True)

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
    print(f"[*] Starting Burp crawl+audit on {URL} ...")
    r = requests.post(
        BRIDGE + "/scan/start",
        headers=HEAD,
        params={"url": URL, "host": HOST},
        timeout=30
    )
    r.raise_for_status()
    data = r.json()
    print(f"[✓] Scan started: {data}")
    return data["scanId"]

def poll_status(scan_id):
    print("[*] Polling scan status (crawl → audit → complete)...")
    fail_count = 0
    while True:
        try:
            s = requests.get(BRIDGE + f"/scan/status?id={scan_id}", headers=HEAD, timeout=30)
            s.raise_for_status()
            data = s.json()
            fail_count = 0  # reset on success
            (ART / "scan-status.json").write_text(json.dumps(data, indent=2))
            print(f"    {data}", flush=True)
            if data.get("complete"):
                return data
            if data.get("error"):
                raise RuntimeError(f"Scan error: {data['error']}")
        except requests.RequestException as e:
            fail_count += 1
            print(f"    [!] Poll failed ({fail_count}/5): {e}", flush=True)
            if fail_count >= 5:
                raise RuntimeError(f"Bridge unreachable after 5 retries: {e}")
            time.sleep(5)
            continue
        time.sleep(15)

def get_report(scan_id):
    print("[*] Generating report...")
    r = requests.post(BRIDGE + f"/scan/report?id={scan_id}", headers=HEAD, timeout=120)
    r.raise_for_status()
    data = r.json()
    (ART / "run-summary.json").write_text(json.dumps({"scanId": scan_id, "report": data}, indent=2))
    print(f"[✓] Report saved: {data['path']}  |  Issues: {data['issues']}")
    return data

def main():
    wait_health()
    scan_id = start_scan()
    status  = poll_status(scan_id)
    report  = get_report(scan_id)
    print(f"\n[✓] DONE — Issues found: {report['issues']}")
    print(f"    Report: {report['path']}")

if __name__ == "__main__":
    main()
