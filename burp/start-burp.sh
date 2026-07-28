#!/usr/bin/env bash
set -euo pipefail

runtime_config=/home/burp/runtime-project-options.json
umask 077
if [[ ! "${TARGET_HOST:-ofbiz}" =~ ^[A-Za-z0-9.-]+$ ]]; then
  echo "TARGET_HOST contains invalid characters" >&2
  exit 1
fi
jq \
  --arg username "${OFBIZ_USERNAME:?OFBIZ_USERNAME is required}" \
  --arg password "${OFBIZ_PASSWORD:?OFBIZ_PASSWORD is required}" \
  --arg target_host "${TARGET_HOST:-ofbiz}" \
  '.scanner.application_logins |= map(
    if .type == "UsernameAndPasswordCredentials"
    then .username = $username | .password = $password
    else .
    end
  )
  | .target.scope.include |= map(.host = ("^" + ($target_host | gsub("\\."; "\\.")) + "$"))
  | .target.scope.exclude |= map(.host = ("^" + ($target_host | gsub("\\."; "\\.")) + "$"))' \
  /opt/burp/project-options.json > "$runtime_config"

exec java -Xmx4g -jar /opt/burp/burpsuite_pro.jar \
  --project-file=/home/burp/ofbiz-agent.burp \
  --config-file="$runtime_config" \
  --user-config-file=/opt/burp/user-options.json
