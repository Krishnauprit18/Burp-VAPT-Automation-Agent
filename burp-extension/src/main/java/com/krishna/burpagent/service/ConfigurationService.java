package com.krishna.burpagent.service;

import burp.api.montoya.MontoyaApi;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

public class ConfigurationService {
    private final MontoyaApi api;
    private final String logFile = "/home/krishna/Pictures/ofbiz-burp-agent/bridge_init.log";

    public ConfigurationService(MontoyaApi api) {
        this.api = api;
    }

    public void logDiagnostics(String msg) {
        try {
            Path p = Path.of(logFile);
            Files.writeString(p, "[" + java.time.Instant.now() + "] " + msg + "\n",
                StandardCharsets.UTF_8,
                java.nio.file.StandardOpenOption.CREATE, java.nio.file.StandardOpenOption.APPEND);
        } catch (Exception ignored) {}
    }

    public String getSecurityToken() {
        String token = System.getenv().getOrDefault("BURP_BRIDGE_TOKEN", "");
        if (token.length() < 32) token = loadTokenFromFile("/home/krishna/Pictures/ofbiz-burp-agent/.env");
        if (token.length() < 32) token = loadTokenFromFile(".env");
        return token;
    }

    private String loadTokenFromFile(String filepath) {
        try {
            Path path = Path.of(filepath);
            if (Files.exists(path)) {
                for (String line : Files.readAllLines(path, StandardCharsets.UTF_8)) {
                    line = line.trim();
                    if (line.startsWith("BURP_BRIDGE_TOKEN=")) {
                        String val = line.substring("BURP_BRIDGE_TOKEN=".length()).trim();
                        if (val.startsWith("\"") && val.endsWith("\"") && val.length() >= 2) {
                            val = val.substring(1, val.length() - 1);
                        }
                        return val;
                    }
                }
            }
        } catch (Exception ignored) {}
        return "";
    }

    public void injectAggressiveScanRules() {
        String user = System.getenv().getOrDefault("OFBIZ_USERNAME", "admin");
        String pass = System.getenv().getOrDefault("OFBIZ_PASSWORD", "ofbiz");

        String optionsJson = String.format("""
        {
          "target": {
            "scope": {
              "advanced_mode": true,
              "include": [
                { "enabled": true, "host": "^ofbiz$", "port": "^8443$", "protocol": "https" },
                { "enabled": true, "host": "^localhost$", "port": "^8443$", "protocol": "https" },
                { "enabled": true, "host": "^127\\\\.0\\\\.0\\\\.1$", "port": "^8443$", "protocol": "https" }
              ],
              "exclude": [
                { "enabled": true, "host": "^.*$", "file": ".*(logout|Logout|checkLogin).*" }
              ]
            }
          },
          "scanner": {
            "application_logins": [
              { "enabled": true, "type": "UsernameAndPasswordCredentials", "username": "%s", "password": "%s" }
            ],
            "crawl_options": {
              "read_timeout_millis": 10000,
              "max_concurrent_requests": 15
            }
          }
        }
        """, user, pass);

        try {
            api.burpSuite().importProjectOptionsFromJson(optionsJson);
            String msg = "Aggressive Scan Configuration & OFBiz Credentials (" + user + ") loaded into Burp Project!";
            logDiagnostics(msg);
            api.logging().logToOutput(msg);
        } catch (Exception e) {
            logDiagnostics("Error importing project options: " + e.getMessage());
        }
    }
}
