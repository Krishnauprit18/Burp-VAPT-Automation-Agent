#!/usr/bin/env bash
set -euo pipefail

# ── Ensure JDK 21 is used for the build ─────────────────────
JAVA21="/usr/lib/jvm/java-21-openjdk-amd64/bin/java"
if [[ -x "$JAVA21" ]]; then
    export JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64
    export PATH=$JAVA_HOME/bin:$PATH
fi
if ! java -version 2>&1 | grep -q "version \"21"; then
    echo "[✗] JDK 21 is required but '$(java -version 2>&1 | head -1)' is active."
    echo "    Install: sudo apt install openjdk-21-jdk"
    exit 1
fi

cd "$(dirname "$0")/burp-extension"
mvn -q clean package
echo "[✓] Extension JAR built: burp-extension/target/burp-agent-bridge.jar"
