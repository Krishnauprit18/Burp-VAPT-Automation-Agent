import json, os, time
from pathlib import Path
import requests

# ── Environment ────────────────────────────────────────────────────────────────
URL         = os.environ.get("OFBIZ_URL", "https://ofbiz:8443/webtools/control/checkLogin")
BRIDGE      = os.environ.get("BURP_BRIDGE_URL", "http://burp:1338")
TOKEN       = os.environ.get("BURP_BRIDGE_TOKEN", "")
TARGET_HOST = os.environ.get("BURP_TARGET_HOST", "ofbiz")
HEAD        = {"Authorization": "Bearer " + TOKEN}
ART         = Path(os.environ.get("ARTIFACTS_DIR", "/artifacts"))
ART.mkdir(parents=True, exist_ok=True)


def wait_health():
    """Poll the Burp bridge /health endpoint until it responds."""
    print(f"[*] Waiting for Burp bridge at {BRIDGE} ...", flush=True)
    for attempt in range(120):
        try:
            r = requests.get(BRIDGE + "/health", headers=HEAD, timeout=3)
            if r.ok:
                print(f"[✓] Burp bridge ready: {r.json()}", flush=True)
                return
        except requests.RequestException:
            pass
        time.sleep(2)
    raise RuntimeError(f"Burp bridge not ready after 240 s at {BRIDGE}")


def run_native_crawl():
    """Trigger Burp's Native Automated Crawler on the target seed URL."""
    print(f"[*] Triggering Burp Native Crawl on seed URL: {URL} ...", flush=True)
    r = requests.post(BRIDGE + f"/crawl/start?url={URL}", headers=HEAD, timeout=30)
    r.raise_for_status()
    crawl_id = r.json()["crawlId"]
    print(f"[✓] Burp Native Crawl task started: id={crawl_id}", flush=True)

    # Poll Crawl status until finished
    while True:
        try:
            s = requests.get(BRIDGE + f"/crawl/status?id={crawl_id}", headers=HEAD, timeout=30)
            s.raise_for_status()
            data = s.json()
            (ART / "crawl-status.json").write_text(json.dumps(data, indent=2))
            print(f"  [Crawl Progress] {data}", flush=True)
            if data.get("complete") or data.get("requests", 0) > 0:
                # Crawl initial phase triggered or completed
                break
        except requests.RequestException as err:
            print(f"[!] Crawl status poll retry: {err}", flush=True)
        time.sleep(10)
    print("[✓] Crawling Phase Completed", flush=True)


def run_active_audit():
    """Trigger Burp's Active Scanner on the discovered Site Tree."""
    print(f"[*] Fetching site-map for host '{TARGET_HOST}'...", flush=True)
    sm = requests.get(BRIDGE + f"/site-map?host={TARGET_HOST}", headers=HEAD, timeout=30)
    sm.raise_for_status()
    (ART / "site-map.json").write_text(json.dumps(sm.json(), indent=2))
    count = sm.json().get("count", 0)
    print(f"[✓] Site-map captured: {count} endpoints", flush=True)

    print("[*] Starting Burp Active Audit on target site tree...", flush=True)
    r = requests.post(BRIDGE + f"/audit/start?host={TARGET_HOST}", headers=HEAD, timeout=30)
    r.raise_for_status()
    audit_id = r.json()["auditId"]
    print(f"[✓] Active Audit started: id={audit_id}, queued={r.json().get('queuedItems', '?')}", flush=True)

    # Poll Audit status until complete
    while True:
        try:
            s = requests.get(BRIDGE + f"/audit/status?id={audit_id}", headers=HEAD, timeout=30)
            s.raise_for_status()
            data = s.json()
            (ART / "audit-status.json").write_text(json.dumps(data, indent=2))
            print(f"  [Audit Progress] {data}", flush=True)
            if data.get("complete"):
                break
        except requests.RequestException as err:
            print(f"[!] Audit status poll retry: {err}", flush=True)
        time.sleep(10)

    # Generate Final Report
    print("[*] Exporting Final VAPT HTML Report...", flush=True)
    rep = requests.post(BRIDGE + f"/audit/report?id={audit_id}", headers=HEAD, timeout=120)
    rep.raise_for_status()
    (ART / "run-summary.json").write_text(
        json.dumps({"auditId": audit_id, "report": rep.json()}, indent=2)
    )
    print(f"[✓] Automated VAPT Pipeline Completed! Report: artifacts/burp-active-scan-report.html", flush=True)


def main():
    wait_health()
    run_native_crawl()
    time.sleep(5)
    run_active_audit()


if __name__ == "__main__":
    main()
