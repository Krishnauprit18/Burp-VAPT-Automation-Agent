#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
info() { echo -e "${CYAN}[*] $*${NC}"; }
success() { echo -e "${GREEN}[✓] $*${NC}"; }
fail() { echo -e "${RED}[x] $*${NC}" >&2; exit 1; }

echo ""
echo -e "${CYAN}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║     OFBiz Docker + Native Burp Suite Pro Pipeline        ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""

# 1. Environment check
[[ -f .env ]] || fail "Missing .env file. Please create one from .env.example."
set -a; source .env; set +a

mkdir -p artifacts

# 2. Build Extension
info "Step 1/4: Ensuring Montoya Extension JAR is built..."
./build.sh >/dev/null
success "Extension JAR ready: $(pwd)/burp-extension/target/burp-agent-bridge.jar"

# 3. Start ONLY OFBiz Container in Docker
info "Step 2/4: Starting OFBiz application in Docker..."
docker compose up -d ofbiz
success "OFBiz container running on https://ofbiz:8443"

# 4. Instructions for Native Burp Suite
echo ""
echo -e "${YELLOW}╔════════════════════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${YELLOW}║  ACTION REQUIRED ON YOUR NATIVE BURP SUITE PRO (One-time):                     ║${NC}"
echo -e "${YELLOW}║                                                                                ║${NC}"
echo -e "${YELLOW}║  1. Open your Native Burp Suite Pro on your desktop.                           ║${NC}"
echo -e "${YELLOW}║  2. Go to Extensions -> Installed -> Click 'Add' -> Select Type: Java          ║${NC}"
echo -e "${YELLOW}║  3. Select File Path:                                                          ║${NC}"
echo -e "${YELLOW}║     $(pwd)/burp-extension/target/burp-agent-bridge.jar             ║${NC}"
echo -e "${YELLOW}╚════════════════════════════════════════════════════════════════════════════════╝${NC}"
echo ""
read -r -p "Press ENTER once extension is loaded in your native Burp UI > "
echo ""

# 5. Execute Python Scan Controller natively
info "Step 3/4: Setting up Python runtime and waiting for bridge..."
VENV="$(pwd)/venv"
if [[ ! -d "$VENV" ]]; then
    python3 -m venv "$VENV"
fi
source "$VENV/bin/activate"
pip install -q --upgrade pip
pip install -q requests==2.32.4 urllib3

export SCAN_SEED_URLS="${SCAN_SEED_URLS:-https://ofbiz:8443/webtools/control/main,https://ofbiz:8443/accounting/control/main,https://ofbiz:8443/catalog/control/main,https://ofbiz:8443/ordermgr/control/main,https://ofbiz:8443/partymgr/control/main,https://ofbiz:8443/facility/control/main,https://ofbiz:8443/content/control/main,https://ofbiz:8443/manufacturing/control/main,https://ofbiz:8443/sfa/control/main,https://ofbiz:8443/workeffort/control/main}"
export TARGET_HOST="${TARGET_HOST:-ofbiz}"
export BURP_BRIDGE_URL="http://localhost:${BURP_BRIDGE_PORT:-1338}"
export BURP_BRIDGE_TOKEN="${BURP_BRIDGE_TOKEN}"
export ARTIFACTS_DIR="$(pwd)/artifacts"

info "Step 4/4: Triggering Burp Crawl & Active Audit Pipeline..."
python3 agent/run.py

report=$(find artifacts -maxdepth 1 -type f -name 'burp-vapt-report-*.html' -printf '%T@ %p\n' \
  | sort -nr | head -1 | cut -d' ' -f2-)

echo ""
echo -e "${GREEN}${BOLD}═══════════════════════════════════════════${NC}"
echo -e "${GREEN}${BOLD}  SCAN COMPLETE!${NC}"
echo -e "${GREEN}  Report generated at: ${report}${NC}"
echo -e "${GREEN}${BOLD}═══════════════════════════════════════════${NC}"
echo ""
xdg-open "$report" 2>/dev/null || true
