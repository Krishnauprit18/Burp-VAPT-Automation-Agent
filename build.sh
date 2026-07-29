#!/usr/bin/env bash
set -euo pipefail

# The launcher and extension target Java 17+, matching OFBiz and modern Burp.
JAVA21="/usr/lib/jvm/java-21-openjdk-amd64/bin/java"
if [[ -x "$JAVA21" ]]; then
    export JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64
    export PATH=$JAVA_HOME/bin:$PATH
fi
java_major=$(java -version 2>&1 | head -1 | sed -E 's/.*version "([0-9]+).*/\1/')
if [[ ! "$java_major" =~ ^[0-9]+$ ]] || (( java_major < 17 )); then
    echo "[x] JDK 17 or newer is required but '$(java -version 2>&1 | head -1)' is active."
    exit 1
fi

cd "$(dirname "$0")/burp-extension"
mvn -q clean package
echo "[+] Java multi-agent JAR built: burp-extension/target/burp-agent-bridge.jar"
