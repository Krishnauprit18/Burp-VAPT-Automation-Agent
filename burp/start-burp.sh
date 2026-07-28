#!/usr/bin/env bash
set -euo pipefail
exec java -Xmx4g -jar /opt/burp/burpsuite_pro.jar \
  --project-file=/home/burp/ofbiz-agent.burp \
  --config-file=/opt/burp/project-options.json \
  --user-config-file=/opt/burp/user-options.json
