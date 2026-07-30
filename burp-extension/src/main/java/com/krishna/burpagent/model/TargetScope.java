package com.krishna.burpagent.model;

import java.net.URI;
import java.util.Locale;

public record TargetScope(String url, String host, int port) {
    public static final String DEFAULT_URL = "https://localhost:8443/webtools/control/main";

    private static final String ECOMMERCE_PREFIX = "/ecommerce/";

    public static TargetScope webTools(String value) {
        URI uri;
        try {
            uri = URI.create(value == null || value.isBlank() ? DEFAULT_URL : value.trim());
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("TARGET_URL must be a valid URI", e);
        }
        int effectivePort = uri.getPort() == -1 ? 443 : uri.getPort();
        if (!"https".equalsIgnoreCase(uri.getScheme())
                || !"localhost".equalsIgnoreCase(uri.getHost())
                || effectivePort != 8443
                || !"/webtools/control/main".equals(uri.getPath())
                || uri.getRawQuery() != null
                || uri.getRawFragment() != null
                || uri.getUserInfo() != null) {
            throw new IllegalArgumentException(
                    "TARGET_URL must be exactly " + DEFAULT_URL);
        }
        return new TargetScope(DEFAULT_URL, "localhost", 8443);
    }

    public boolean allowsPath(String path) {
        if (path == null) return false;
        String normalized = path.toLowerCase(Locale.ROOT);
        return !normalized.equals("/ecommerce") && !normalized.startsWith(ECOMMERCE_PREFIX);
    }

    public boolean isLogoutPath(String path) {
        if (path == null) return false;
        String normalized = path.toLowerCase(Locale.ROOT);
        return normalized.matches("^/[^/]+/control/logout(?:/.*)?$");
    }

    public boolean isLoginPath(String path) {
        if (path == null) return false;
        String normalized = path.toLowerCase(Locale.ROOT);
        return normalized.matches("^/[^/]+/control/login(?:/.*)?$");
    }

    public boolean usesPrimaryApplicationSession(String path) {
        if (path == null) return false;
        String normalized = path.toLowerCase(Locale.ROOT);
        return normalized.equals("/webtools") || normalized.startsWith("/webtools/");
    }
}
