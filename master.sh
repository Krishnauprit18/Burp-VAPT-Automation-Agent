#!/usr/bin/env bash
# ============================================================
# OFBiz Burp Agent — Master Script
# Usage: ./master.sh
# ============================================================
set -euo pipefail
cd "$(dirname "$0")"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
info()    { echo -e "${CYAN}[*]${NC} $*"; }
success() { echo -e "${GREEN}[✓]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
error()   { echo -e "${RED}[✗]${NC} $*"; exit 1; }

# ── Load .env ────────────────────────────────────────────────
[[ -f .env ]] || cp .env.example .env
set -a; source .env; set +a

TOKEN="${BURP_BRIDGE_TOKEN}"
BRIDGE_PORT="${BURP_BRIDGE_PORT:-1338}"
PROXY_PORT="${BURP_PROXY_PORT:-8080}"
VENV=".venv-agent"

echo ""
echo -e "${CYAN}${BOLD}╔══════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}${BOLD}║      OFBiz Burp VAPT — Master Runner        ║${NC}"
echo -e "${CYAN}${BOLD}╚══════════════════════════════════════════════╝${NC}"
echo ""

# ── SESSION SELECTION ─────────────────────────────────────────
echo -e "${BOLD}Burp Session Select karo:${NC}"
echo -e "  ${GREEN}1${NC}) Pichla saved session load karo (agar pehle kaam ho chuka hai)"
echo -e "  ${GREEN}2${NC}) Naya fresh session shuru karo"
echo ""
read -r -p "  Enter choice [1/2]: " SESSION_CHOICE

case "$SESSION_CHOICE" in
    1)
        success "Previous session use hogi (burp-home volume intact)"
        NEW_SESSION=false
        ;;
    2)
        warn "New session: burp-home volume delete ho jayega (pichla project clear)"
        read -r -p "  Confirm? [y/N]: " CONFIRM
        if [[ "$CONFIRM" =~ ^[Yy]$ ]]; then
            docker volume rm ofbiz-burp-agent_burp-home 2>/dev/null && \
                success "burp-home volume cleared — fresh session hogi" || \
                info "Volume already clean"
            NEW_SESSION=true
        else
            info "Cancelled — previous session use hogi"
            NEW_SESSION=false
        fi
        ;;
    *)
        warn "Invalid choice, defaulting to previous session"
        NEW_SESSION=false
        ;;
esac
echo ""

# ── STEP 1: JAR check ────────────────────────────────────────
info "STEP 1/6: Checking Burp JAR..."
if [[ ! -f burp/burpsuite_pro.jar ]]; then
    JAR=$(ls burp/burpsuite*.jar 2>/dev/null | head -1)
    if [[ -n "$JAR" ]]; then
        ln -sf "$(basename "$JAR")" burp/burpsuite_pro.jar
        success "Symlink created: burpsuite_pro.jar → $(basename "$JAR")"
    else
        error "No Burp JAR found in burp/. Place burpsuite_pro.jar there."
    fi
else
    REAL=$(readlink burp/burpsuite_pro.jar 2>/dev/null || echo "direct jar")
    success "Burp JAR OK ($REAL)"
fi

# ── STEP 2: Maven build ──────────────────────────────────────
info "STEP 2/6: Building Burp extension (Maven)..."
if [[ -d /usr/lib/jvm/java-21-openjdk-amd64 ]]; then
    export JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64
    export PATH=$JAVA_HOME/bin:$PATH
fi
cd burp-extension && mvn -q clean package && cd ..
success "Extension JAR built: burp-extension/target/burp-agent-bridge.jar"

# ── STEP 3: /etc/hosts entry ─────────────────────────────────
info "STEP 3/6: Checking /etc/hosts for 'ofbiz'..."
if ! grep -q "^127.0.0.1 ofbiz$" /etc/hosts 2>/dev/null; then
    echo '127.0.0.1 ofbiz' | sudo tee -a /etc/hosts > /dev/null
    success "Added '127.0.0.1 ofbiz' to /etc/hosts"
else
    success "'ofbiz' already in /etc/hosts"
fi

# ── STEP 4: Start containers ─────────────────────────────────
info "STEP 4/6: Starting OFBiz + Burp containers..."
xhost +SI:localuser:"$(id -un)" > /dev/null 2>&1 || true
docker compose up -d --build ofbiz burp
success "Containers started"

if [[ "$NEW_SESSION" == "true" ]]; then
    echo ""
    warn "NEW SESSION: Burp UI khulegi — pehle 'Temporary project' choose karo ya default"
    warn "Phir Extension tab → Add → burp-agent-bridge.jar load karo"
else
    echo ""
    info "PREVIOUS SESSION: Burp pichla project auto-load karega"
    warn "Agar extension nahi load hua — Extension tab → Add → burp-agent-bridge.jar"
fi
echo ""

# ── STEP 5: Wait for OFBiz ───────────────────────────────────
info "STEP 5/6: Waiting for OFBiz to be ready..."
for i in $(seq 1 60); do
    HTTP=$(curl -sk -o /dev/null -w "%{http_code}" \
           https://ofbiz:8443/webtools/control/main 2>/dev/null || echo "0")
    if [[ "$HTTP" == "200" ]]; then
        success "OFBiz ready (HTTP $HTTP)"
        break
    fi
    [[ $i -eq 60 ]] && error "OFBiz not ready after 2 min. Check: docker logs ofbiz-agent-ofbiz"
    echo -ne "\r    Waiting for OFBiz... ${i}/60 (HTTP: ${HTTP})"
    sleep 2
done

# ── STEP 6: Wait for Burp Bridge ─────────────────────────────
info "STEP 6/6: Waiting for Burp Bridge (port $BRIDGE_PORT)..."
echo ""
echo -e "  ${BOLD}ACTION REQUIRED in Burp UI:${NC}"
echo -e "  Extensions tab → Installed → Add → Java"
echo -e "  File: ${YELLOW}/opt/burp/extensions/burp-agent-bridge.jar${NC}"
echo ""
read -r -p "  Extension add karne ke baad ENTER dabao > "
echo ""

for i in $(seq 1 30); do
    RESP=$(curl -s --max-time 3 \
           http://localhost:"$BRIDGE_PORT"/health \
           -H "Authorization: Bearer $TOKEN" 2>/dev/null || true)
    if echo "$RESP" | grep -q '"ok":true'; then
        success "Burp Bridge READY! $RESP"
        break
    fi
    [[ $i -eq 30 ]] && error "Bridge not ready. Extension sahi load hua? Burp Output tab check karo."
    echo -ne "\r    Checking bridge... ${i}/30"
    sleep 2
done

# ── Run Scan ─────────────────────────────────────────────────
echo ""
info "Setting up Python agent and starting scan..."

if [[ ! -d "$VENV" ]]; then
    python3 -m venv "$VENV"
fi
source "$VENV/bin/activate"
pip install -q --upgrade pip
pip install -q playwright==1.54.0 requests==2.32.4
playwright install chromium > /dev/null 2>&1 || true
success "Python env ready"

echo ""
info "Scan chal raha hai — terminal band mat karo..."
echo ""

export OFBIZ_URL="https://ofbiz:8443/webtools/control/main"
export BURP_PROXY="http://localhost:${PROXY_PORT}"
export BURP_BRIDGE_URL="http://localhost:${BRIDGE_PORT}"
export ARTIFACTS_DIR="$(pwd)/artifacts"

python3 agent/run.py

echo ""
echo -e "${GREEN}${BOLD}═══════════════════════════════════════════${NC}"
echo -e "${GREEN}${BOLD}  SCAN COMPLETE!${NC}"
echo -e "${GREEN}  Report: artifacts/burp-active-scan-report.html${NC}"
echo -e "${GREEN}${BOLD}═══════════════════════════════════════════${NC}"
echo ""
xdg-open artifacts/burp-active-scan-report.html 2>/dev/null || true
