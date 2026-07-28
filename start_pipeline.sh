#!/usr/bin/env bash
# ============================================================
# OFBiz Burp VAPT — Single Automated Pipeline Launcher
# ============================================================
set -euo pipefail
cd "$(dirname "$0")"

GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'

echo ""
echo -e "${CYAN}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║    OFBiz + Burp Suite Pro Automated VAPT Pipeline        ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""

# 1. Environment check
[[ -f .env ]] || cp .env.example .env
set -a; source .env; set +a

# 2. Check Burp Pro JAR
if [[ ! -f burp/burpsuite_pro.jar ]]; then
    JAR=$(ls burp/burpsuite*.jar 2>/dev/null | grep -v "burpsuite_pro.jar" | head -1)
    if [[ -n "$JAR" ]]; then
        ln -sf "$(basename "$JAR")" burp/burpsuite_pro.jar
        echo -e "${GREEN}[✓] Burp JAR linked: $(basename "$JAR")${NC}"
    else
        echo -e "${RED}[✗] Missing burpsuite_pro.jar in burp/ directory.${NC}"
        exit 1
    fi
fi

# 3. Build Extension JAR
echo -e "${CYAN}[*] Step 1/3: Building Burp Extension...${NC}"
./build.sh > /dev/null

# 4. Start Containers
echo -e "${CYAN}[*] Step 2/3: Starting OFBiz & Burp Containers...${NC}"
xhost +SI:localuser:"$(id -un)" >/dev/null 2>&1 || true
docker compose up -d --build ofbiz burp

echo ""
echo -e "${YELLOW}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${YELLOW}║  ACTION REQUIRED (One-time in Burp GUI):                 ║${NC}"
echo -e "${YELLOW}║                                                          ║${NC}"
echo -e "${YELLOW}║  1. In Burp Suite UI window -> Extensions -> Installed   ║${NC}"
echo -e "${YELLOW}║  2. Click 'Add' -> Select Type: Java                     ║${NC}"
echo -e "${YELLOW}║  3. File: /opt/burp/extensions/burp-agent-bridge.jar     ║${NC}"
echo -e "${YELLOW}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""
read -r -p "Press ENTER once extension is loaded in Burp UI > "
echo ""

# 5. Run Automated Pipeline Agent (Native Crawl + Active Audit)
echo -e "${CYAN}[*] Step 3/3: Running Burp Native Crawl & Active Scan...${NC}"
docker compose --profile run run --rm capture-agent

echo ""
echo -e "${GREEN}[✓] Pipeline execution finished!${NC}"
echo -e "${GREEN}[✓] Report saved at: artifacts/burp-active-scan-report.html${NC}"
