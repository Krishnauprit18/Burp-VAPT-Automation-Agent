#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

fail() { echo "[x] $*" >&2; exit 1; }
info() { echo "[*] $*"; }

[[ -f .env ]] || fail "Create .env from .env.example and replace every placeholder."
command -v docker >/dev/null || fail "docker is required"
docker compose version >/dev/null 2>&1 || fail "Docker Compose v2 is required"
[[ -f burp/burpsuite_pro.jar ]] || fail "Place your licensed Burp Professional JAR at burp/burpsuite_pro.jar"

if grep -Eq 'replace-me|replace-with|/absolute/path' .env; then
    fail ".env still contains example placeholders"
fi

mkdir -p artifacts

info "Building the Montoya extension"
./build.sh

info "Building containers"
docker compose --profile run build ofbiz burp capture-agent

info "Stopping any previous scan containers"
docker compose down --remove-orphans

if docker volume inspect burp-vapt-ofbiz-runtime >/dev/null 2>&1; then
    info "Removing the previous isolated OFBiz runtime volume"
    docker volume rm burp-vapt-ofbiz-runtime >/dev/null
fi

info "Creating a fresh Burp project while retaining Burp licence data"
docker compose run --rm --no-deps --entrypoint sh burp -c \
  'rm -f /home/burp/ofbiz-agent.burp /home/burp/ofbiz-agent.burp.backup /home/burp/ofbiz-agent.burp.lck'

xhost +SI:localuser:"$(id -un)" >/dev/null 2>&1 || true

info "Starting OFBiz and Burp"
docker compose up -d ofbiz burp

info "Starting native Burp crawl followed by active audit"
docker compose --profile run run --rm capture-agent

report=$(find artifacts -maxdepth 1 -type f -name 'burp-vapt-report-*.html' -printf '%T@ %p\n' \
  | sort -nr | head -1 | cut -d' ' -f2-)
[[ -n "$report" ]] || fail "Scan finished but no report was generated"

echo "[+] Scan complete"
echo "[+] Report: $report"
