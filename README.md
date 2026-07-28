# OFBiz + Burp Professional automated VAPT

Deterministic, LLM-free automation for an authorised OFBiz test environment.

## What one scan does

1. Builds and starts the selected OFBiz source tree in Docker.
2. Starts the licensed Burp Suite Professional JAR in Docker.
3. Automatically loads the local Java/Montoya bridge extension.
4. Waits for OFBiz and Burp to become ready.
5. Starts Burp's native browser-powered crawler from the configured seed URLs.
6. Waits for crawler status or a bounded period with no new crawl requests.
7. Collects the target host's authenticated Site Map entries.
8. Starts a Burp active audit and waits with a hard timeout.
9. Generates a uniquely named HTML report and JSON run metadata.

No browser-driving framework, manually captured traffic, or LLM is used.

## Stack

- Java 21 and the official Montoya API for in-process Burp control.
- A small Python 3.12 coordinator for readiness checks and bridge polling.
- Docker Compose for OFBiz, Burp, and coordinator lifecycle.
- Bash for the single host-side entry point.

## Requirements

- Linux with an X11 session.
- Docker Engine with Docker Compose v2.
- Maven and JDK 21.
- A legitimate Burp Suite Professional licence and JAR.
- An OFBiz source tree with a working Dockerfile.

Burp Professional is a desktop product. This project containerises the official
JAR supplied by the user; it does not redistribute Burp or a licence.

## First-time setup

```bash
cp .env.example .env
chmod 600 .env
```

Replace every placeholder in `.env`, then place your Burp Professional JAR at:

```text
burp/burpsuite_pro.jar
```

The first Burp launch may require licence activation in the forwarded UI. That is
a PortSwigger licensing step. Once the persistent `burp-home` volume is activated,
subsequent scans do not require the extension to be added manually.

## Run

```bash
./start_pipeline.sh
```

The runner intentionally creates a fresh Burp project for every scan so requests
from a previous OFBiz release cannot leak into the next report. Licence state is
retained separately in the persistent Burp home volume. It also deletes and
recreates the isolated `burp-vapt-ofbiz-runtime` Docker volume so application
state from a previous release is not reused.

Generated files are written under `artifacts/`, including:

```text
scan-status.json
run-summary.json
burp-vapt-report-<scan-id>.html
```

Stop the environment with:

```bash
./stop.sh
```

## Safety and scope

- Every seed URL must use HTTP(S) and its host must exactly match `TARGET_HOST`.
- Only one scan can run at a time.
- The bridge is published on host loopback and requires a 32+ character token.
- Login and logout requests are excluded from active auditing.
- Crawl and audit phases have explicit maximum durations.
- Run active scanning only against isolated, authorised test environments.

## Important Burp API limitation

Montoya 2026.7 exposes the native `startCrawl()` operation, but the current
`Crawl.statusMessage()` documentation says its status functionality is not yet
implemented. The extension therefore uses two bounded completion signals:

1. a terminal status when Burp supplies one; or
2. `CRAWL_IDLE_SECONDS` without an increase in crawler request count, after
   which the crawl task is stopped before the audit begins.

This is deterministic and cannot hang forever, but an idle window is still a
heuristic. Increase `CRAWL_IDLE_SECONDS` for slow applications.

The public Montoya audit API currently exposes
`LEGACY_ACTIVE_AUDIT_CHECKS`; it does not expose the desktop scan launcher's
named **Balanced** preset. The project therefore performs a real Burp active
audit, but must not claim that it programmatically selects the Balanced preset.

For a vendor-supported CI/scheduling API with first-class scan state, use Burp
Suite DAST. This project is appropriate when the company specifically chooses
to automate an existing Burp Professional licence.
