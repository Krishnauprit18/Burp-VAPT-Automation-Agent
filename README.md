# OFBiz + Burp Professional deterministic scan agents

This replaces the previous ZAP chain with Burp Professional:

1. Docker deploys OFBiz.
2. Docker launches Burp Pro with Linux X11 UI forwarding.
3. A Playwright agent logs in and runs the URLs in `workflows/urls.txt` through Burp Proxy.
4. Burp builds Proxy history/Site Map and performs normal passive analysis.
5. A local Montoya extension starts a Burp **BALANCED active audit** on captured authenticated `/webtools/control/*` traffic.
6. The agent polls completion and saves `artifacts/burp-active-scan-report.html`.

No LLM is used.

## Requirements

- Linux with X11 session
- Docker + Docker Compose
- Maven and JDK 21
- Legitimate Burp Suite Professional licence/JAR
- OFBiz source tree containing its Dockerfile

## Setup

```bash
unzip ofbiz-burp-agent.zip
cd ofbiz-burp-agent
cp .env.example .env
nano .env
```

Set `OFBIZ_SOURCE`, credentials, and a long random `BURP_BRIDGE_TOKEN`.

Download Burp Professional JAR from your PortSwigger account and place it at:

```text
burp/burpsuite_pro.jar
```

Start:

```bash
./run.sh
```

Burp UI opens through X11. On the first run, activate your own licence and let Burp finish opening. Its home/project are persisted in the `burp-home` Docker volume.

Run the automated browser capture + active audit:

```bash
./scan.sh
```

Output:

```text
artifacts/site-map.json
artifacts/audit-status.json
artifacts/run-summary.json
artifacts/burp-active-scan-report.html
```

Stop:

```bash
./stop.sh
```

## Important boundaries

The extension only audits captured traffic whose host is `ofbiz`, whose path begins `/webtools/control/`, and excludes login/logout. Change `workflows/urls.txt` for your application flow. Run only against systems you are authorised to test.

## Notes

Burp Desktop has no official Docker image in this project. The Dockerfile runs the official Burp Pro JAR supplied by you. X11 only redirects the desktop UI; Burp itself still runs inside the container.
