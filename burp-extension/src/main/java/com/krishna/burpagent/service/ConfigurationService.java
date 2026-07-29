package com.krishna.burpagent.service;

import burp.api.montoya.MontoyaApi;
import com.krishna.burpagent.model.TargetScope;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.regex.Pattern;

public class ConfigurationService {
    private final MontoyaApi api;
    private final TargetScope target;
    private final Path artifactsDirectory;
    private final Path logFile;

    public ConfigurationService(MontoyaApi api) {
        this.api = api;
        this.target = TargetScope.webTools(environment("TARGET_URL", TargetScope.DEFAULT_URL));
        this.artifactsDirectory = Path.of(environment("ARTIFACTS_DIR", "artifacts"))
                .toAbsolutePath().normalize();
        this.logFile = artifactsDirectory.resolve("bridge.log");
    }

    public void logDiagnostics(String msg) {
        try {
            Files.createDirectories(artifactsDirectory);
            Files.writeString(logFile, "[" + java.time.Instant.now() + "] " + msg + "\n",
                StandardCharsets.UTF_8,
                java.nio.file.StandardOpenOption.CREATE, java.nio.file.StandardOpenOption.APPEND);
        } catch (Exception ignored) {}
    }

    public String getSecurityToken() {
        return environment("BURP_BRIDGE_TOKEN", "");
    }

    public String targetHost() {
        return target.host();
    }

    public int targetPort() {
        return target.port();
    }

    public String targetUrl() {
        return target.url();
    }

    public String ofbizUsername() {
        return environment("OFBIZ_USERNAME", "admin");
    }

    public String ofbizPassword() {
        return environment("OFBIZ_PASSWORD", "ofbiz");
    }

    public boolean isAllowedPath(String path) {
        return target.allowsPath(path);
    }

    public boolean isLogoutPath(String path) {
        return target.isLogoutPath(path);
    }

    public boolean isLoginPath(String path) {
        return target.isLoginPath(path);
    }

    public boolean isCrawlerNavigationTrap(String path) {
        return target.isCrawlerNavigationTrap(path);
    }

    public boolean usesPrimaryApplicationSession(String path) {
        return target.usesPrimaryApplicationSession(path);
    }

    public Path artifactsDirectory() {
        return artifactsDirectory;
    }

    public String environment(String name, String defaultValue) {
        String value = System.getenv(name);
        return value == null || value.isBlank() ? defaultValue : value.trim();
    }

    public long environmentLong(String name, long defaultValue) {
        String value = System.getenv(name);
        if (value == null || value.isBlank()) return defaultValue;
        try {
            return Long.parseLong(value.trim());
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException(name + " must be an integer", e);
        }
    }

    public void applyProjectScope() {
        String optionsJson = buildProjectOptionsJson(targetHost(), targetPort());

        try {
            api.burpSuite().importProjectOptionsFromJson(optionsJson);
            String msg = "Burp project configuration loaded with WebTools seed, "
                    + "Ecommerce exclusion, and logout protection for " + targetUrl();
            logDiagnostics(msg);
            api.logging().logToOutput(msg);
        } catch (Exception e) {
            logDiagnostics("Error importing project options: " + e.getMessage());
            throw new IllegalStateException("Burp rejected the project scope configuration", e);
        }
    }

    static String buildProjectOptionsJson(
            String host,
            int port) {
        String hostPattern = "^" + Pattern.quote(host) + "$";
        return String.format("""
        {
          "target": {
            "scope": {
              "advanced_mode": true,
              "include": [
                {
                  "enabled": true,
                  "host": "%s",
                  "port": "^%d$",
                  "protocol": "https",
                  "file": "^/.*"
                }
              ],
              "exclude": [
                {
                  "enabled": true,
                  "host": "%s",
                  "port": "^%d$",
                  "protocol": "https",
                  "file": "(?i)^/ecommerce(?:/.*)?$"
                },
                {
                  "enabled": true,
                  "host": "%s",
                  "port": "^%d$",
                  "protocol": "https",
                  "file": "(?i)^/[^/]+/control/logout(?:/.*)?$"
                },
                {
                  "enabled": true,
                  "host": "%s",
                  "port": "^%d$",
                  "protocol": "https",
                  "file": "(?i)^/(?:webtools/control/(?:ListLocales|setSessionLocale|setUserLocale|ListVisualThemes|selectTheme|setUserPreference)|common-js/control/SetTimeZoneFromBrowser)$"
                }
              ]
            }
          }
        }
        """, jsonEscape(hostPattern), port,
                jsonEscape(hostPattern), port,
                jsonEscape(hostPattern), port,
                jsonEscape(hostPattern), port);
    }

    private static String jsonEscape(String value) {
        return value.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}
