# OFBiz & Native Burp Professional Automated VAPT Pipeline

An automated Vulnerability Assessment and Penetration Testing (VAPT) pipeline for Apache OFBiz, leveraging Docker and a native installation of Burp Suite Professional.

This system provides a seamless bridge between a containerised target (OFBiz) and a natively running Burp Suite instance. It fully automates the creation, configuration, execution, and state persistence of Burp scan tasks using the Desktop REST API and the Montoya extension framework.

---

## Prerequisites

Ensure the following dependencies are installed and functioning on your system:
- A Linux desktop environment.
- Activated Burp Suite Professional with the Desktop REST API enabled.
- Docker Engine with Docker Compose v2.
- JDK 17+ and Apache Maven.
- Apache OFBiz source files located alongside its standard Dockerfile.

---

## Project Structure

- `burp-extension/`: Contains the Java source code for the automation bridge.
- `config/`: Contains the JSON configuration files that control the Burp scan parameters, scope, and credentials.
- `artifacts/`: Stores generated reports, scan state files, logs, and `.burp` project files for each scan run.
- `Saved-Projects/`: A designated directory for permanently storing valuable Burp scan runs to prevent accidental deletion.

---

## Configuration Guide

Before running the pipeline, configure the environment and scan properties.

### 1. Environment Setup

Create the local environment configuration file:
```bash
cp .env.example .env
chmod 600 .env
```
Inside Burp Suite Professional, enable the Desktop REST API and generate an API key. Populate the `.env` file with the REST API URL (e.g., `http://127.0.0.1:1337`) and the generated key.

Generate a secure token for the Montoya bridge:
```bash
openssl rand -hex 32
```
Add the generated value to `BURP_BRIDGE_TOKEN` in the `.env` file.

### 2. Custom Scan Configuration

The agent strictly follows your provided JSON configuration files located in the `config/` directory.

- `config/ofbiz-credConfig.json`: Used by the agent to extract the target application login credentials.
- `config/ofbiz-scanConfig.json`: Contains the scan rules (e.g., maximum concurrent requests, audit optimisation, error thresholds).
- `config/ofbiz-scandetails-config.json`: Defines the target scope, inclusion paths, and exclusion paths (e.g., skipping the logout endpoint).

These configurations are injected directly into the Burp REST API as Custom Configuration payloads. Modify these JSON files as required prior to initiating a scan.

---

## Execution Guide

### 1. Build the Agent
Compile the Java launcher and extension JAR:
```bash
./build.sh
```

### 2. Validate Configuration
Verify that your configuration and environment variables are valid without starting Docker or Burp:
```bash
java -jar burp-extension/target/burp-agent-bridge.jar --check
```

### 3. Run the Pipeline
Initiate the agent interactively:
```bash
java -jar burp-extension/target/burp-agent-bridge.jar
```
If a previous scan was paused or interrupted (e.g., via Ctrl+C), the agent will detect the saved state and prompt you with the following interactive menu:
```text
[R] Resume monitoring  [N] New scan  [Q] Quit
```
- Select `N` to start a completely fresh scan.
- Select `R` to reload the previous `.burp` project file and resume the scan exactly where it was interrupted. 

Alternatively, use flags to bypass the prompt in automated environments:
```bash
java -jar burp-extension/target/burp-agent-bridge.jar --new
java -jar burp-extension/target/burp-agent-bridge.jar --resume
```

### 4. Cleanup
To stop all managed background processes, containers, and delete generated artifacts (excluding saved projects):
```bash
java -jar burp-extension/target/burp-agent-bridge.jar --stop-clean
```

---

## Outputs and Artifacts

Every unique scan generates a timestamped directory under `artifacts/` (e.g., `artifacts/run-20260731-104333/`). Each directory contains:
- `burp-project.burp`: The complete native Burp Suite project file.
- `agent-state.json`: The persisted progress state of the scan.
- `scan-status.json`: Real-time metrics and status provided by the REST API.
- `bridge.log`: Log output from the Montoya extension.
- `burp-native.log`: Standard output from the Burp executable.

Once a scan succeeds, HTML and XML reports are automatically generated within this directory. To view historical vulnerabilities, you may open the `.burp` project file directly in your standard Burp Suite application.

---

## Architecture Summary

This pipeline uses a dual-interface approach:
1. **Burp Desktop REST API**: Handles the initialisation of the crawl-and-audit task, applying the custom JSON configurations, and monitoring the overall progress metrics.
2. **Montoya Extension Bridge**: Loaded directly into Burp Suite to handle session recovery (re-authenticating OFBiz if the session drops), logging, and generating the final HTML/XML reports. 

This hybrid design ensures robust execution without requiring browser-driving frameworks or brittle synthetic completion heuristics.
