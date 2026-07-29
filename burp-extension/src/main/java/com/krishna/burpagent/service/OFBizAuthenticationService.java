package com.krishna.burpagent.service;

import burp.api.montoya.MontoyaApi;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URLEncoder;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.ReentrantLock;

public final class OFBizAuthenticationService {
    private static final String PROTECTED_VERIFICATION_PATH =
            "/webtools/control/entitymaint";

    private final MontoyaApi api;
    private final ConfigurationService config;
    private final String host;
    private final int port;
    private final String username;
    private final String password;
    private final AtomicReference<String> sessionId = new AtomicReference<>("");
    private final AtomicBoolean refreshRequested = new AtomicBoolean(false);
    private final ReentrantLock loginLock = new ReentrantLock();
    private final ScheduledExecutorService monitor;
    private final SSLContext sslContext;

    public OFBizAuthenticationService(MontoyaApi api, ConfigurationService config) {
        this.api = api;
        this.config = config;
        this.host = config.targetHost();
        this.port = config.targetPort();
        this.username = config.environment("OFBIZ_USERNAME", "admin");
        this.password = config.environment("OFBIZ_PASSWORD", "ofbiz");
        this.sslContext = localTestSslContext();
        this.monitor = Executors.newSingleThreadScheduledExecutor(runnable -> {
            Thread thread = new Thread(runnable, "ofbiz-session-monitor");
            thread.setDaemon(true);
            return thread;
        });
    }

    public void startMonitoring() {
        long seconds = config.environmentLong("SESSION_CHECK_SECONDS", 60);
        monitor.scheduleWithFixedDelay(this::monitorSession, seconds, seconds, TimeUnit.SECONDS);
    }

    public void stop() {
        monitor.shutdownNow();
    }

    public String currentSessionId() {
        if (sessionId.get().isBlank() || refreshRequested.get()) {
            ensureAuthenticated();
        }
        return sessionId.get();
    }

    public void ensureAuthenticated() {
        loginLock.lock();
        try {
            String current = sessionId.get();
            if (!current.isBlank() && !refreshRequested.get() && verify(current)) return;
            authenticate();
        } finally {
            loginLock.unlock();
        }
    }

    public void requestRefresh(String observedSessionId, String reason) {
        String current = sessionId.get();
        if (observedSessionId != null && !observedSessionId.isBlank() && !observedSessionId.equals(current)) {
            return; // This response belongs to an older session that has already been replaced.
        }
        sessionId.compareAndSet(current, "");
        if (refreshRequested.compareAndSet(false, true)) {
            config.logDiagnostics("[Session agent] Session invalidated: " + reason);
            monitor.execute(() -> {
                try {
                    ensureAuthenticated();
                } catch (Exception e) {
                    api.logging().logToError("[Session agent] Re-authentication failed: " + e.getMessage());
                }
            });
        }
    }

    private void monitorSession() {
        try {
            String current = sessionId.get();
            if (current.isBlank() || !verify(current)) {
                requestRefresh(current, "periodic protected-page verification failed");
            }
        } catch (Exception e) {
            config.logDiagnostics("[Session agent] Verification deferred: " + e.getMessage());
        }
    }

    private void authenticate() {
        try {
            HttpResult loginPage = request("GET", "/webtools/control/login", null, null);
            String initialSession = extractSessionId(loginPage.headers());
            String form = "USERNAME=" + encode(username) + "&PASSWORD=" + encode(password);
            HttpResult login = request("POST", "/webtools/control/login", form, initialSession);
            String authenticatedSession = extractSessionId(login.headers());
            if (authenticatedSession.isBlank()) authenticatedSession = initialSession;
            if (authenticatedSession.isBlank() || !verify(authenticatedSession)) {
                throw new IllegalStateException("OFBiz rejected the configured credentials or did not create an authenticated session");
            }
            sessionId.set(authenticatedSession);
            refreshRequested.set(false);
            config.logDiagnostics("[Session agent] Authenticated OFBiz user " + username + " with a fresh JSESSIONID");
            api.logging().logToOutput("[Session agent] Authenticated OFBiz user " + username + "; dynamic session renewal armed.");
        } catch (Exception e) {
            refreshRequested.set(true);
            throw new IllegalStateException("OFBiz authentication failed: " + e.getMessage(), e);
        }
    }

    private boolean verify(String candidate) {
        if (candidate == null || candidate.isBlank()) return false;
        try {
            HttpResult result = request("GET", PROTECTED_VERIFICATION_PATH, null, candidate);
            if (result.status() == 401) return false;
            String location = result.firstHeader("location").toLowerCase(Locale.ROOT);
            if (location.contains("login") || location.contains("checklogin")) return false;
            String body = result.body().toLowerCase(Locale.ROOT);
            boolean loginForm = body.contains("name=\"username\"") && body.contains("name=\"password\"");
            return result.status() >= 200 && result.status() < 400 && !loginForm;
        } catch (Exception e) {
            config.logDiagnostics("[Session agent] Protected-page verification error: " + e.getMessage());
            return false;
        }
    }

    private HttpResult request(String method, String path, String body, String cookie)
            throws IOException {
        HttpsURLConnection connection = (HttpsURLConnection) new URL(
                "https://" + host + ":" + port + path).openConnection();
        connection.setSSLSocketFactory(sslContext.getSocketFactory());
        HostnameVerifier localVerifier = (hostname, session) -> hostname.equalsIgnoreCase(host);
        connection.setHostnameVerifier(localVerifier);
        connection.setRequestMethod(method);
        connection.setConnectTimeout(10_000);
        connection.setReadTimeout(30_000);
        connection.setInstanceFollowRedirects(false);
        connection.setRequestProperty("User-Agent", "OFBiz-Burp-Authentication-Agent/1.0");
        if (cookie != null && !cookie.isBlank()) {
            connection.setRequestProperty("Cookie", "JSESSIONID=" + cookie);
        }
        if (body != null) {
            connection.setDoOutput(true);
            connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8");
            byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
            connection.setFixedLengthStreamingMode(bytes.length);
            try (OutputStream output = connection.getOutputStream()) {
                output.write(bytes);
            }
        }
        int status = connection.getResponseCode();
        InputStream stream = status >= 400 ? connection.getErrorStream() : connection.getInputStream();
        String responseBody;
        if (stream == null) {
            responseBody = "";
        } else {
            try (stream) {
                responseBody = new String(stream.readNBytes(1_000_000), StandardCharsets.UTF_8);
            }
        }
        Map<String, List<String>> headers = connection.getHeaderFields();
        connection.disconnect();
        return new HttpResult(status, headers, responseBody);
    }

    private String extractSessionId(Map<String, List<String>> headers) {
        for (Map.Entry<String, List<String>> entry : headers.entrySet()) {
            if (entry.getKey() == null || !entry.getKey().equalsIgnoreCase("Set-Cookie")) continue;
            for (String header : entry.getValue()) {
                for (String part : header.split(";")) {
                    String trimmed = part.trim();
                    if (trimmed.regionMatches(true, 0, "JSESSIONID=", 0, "JSESSIONID=".length())) {
                        return trimmed.substring("JSESSIONID=".length()).trim();
                    }
                }
            }
        }
        return "";
    }

    private String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    private SSLContext localTestSslContext() {
        try {
            TrustManager[] trustManagers = {new X509TrustManager() {
                public void checkClientTrusted(X509Certificate[] chain, String authType) {}
                public void checkServerTrusted(X509Certificate[] chain, String authType) {}
                public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
            }};
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(null, trustManagers, new SecureRandom());
            return context;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Cannot initialize localhost OFBiz TLS context", e);
        }
    }

    private record HttpResult(int status, Map<String, List<String>> headers, String body) {
        String firstHeader(String name) {
            return headers.entrySet().stream()
                    .filter(entry -> entry.getKey() != null && entry.getKey().equalsIgnoreCase(name))
                    .flatMap(entry -> entry.getValue().stream())
                    .findFirst().orElse("");
        }
    }
}
