package com.krishna.burpagent.service;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.util.Locale;
import java.util.concurrent.atomic.AtomicReference;

public class SessionAuthenticationHandler implements HttpHandler {
    private final MontoyaApi api;
    private final ConfigurationService configService;
    private final AtomicReference<String> goldenAdminCookie = new AtomicReference<>("");

    public SessionAuthenticationHandler(MontoyaApi api, ConfigurationService configService) {
        this.api = api;
        this.configService = configService;
    }

    /**
     * Lock the authenticated Administrator session token.
     * Only callable by deterministic authentication handlers (never from crawler traffic).
     */
    public void setSessionCookie(String cookieValue) {
        if (cookieValue != null && !cookieValue.isBlank()) {
            goldenAdminCookie.set(cookieValue.trim());
            configService.logDiagnostics("[SessionLock] Golden Administrator JSESSIONID secured: " + cookieValue.substring(0, Math.min(15, cookieValue.length())) + "...");
        }
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
        try {
            // 1. Strict Target Scope Security Check: Never leak tokens out-of-scope
            String host = requestToBeSent.httpService().host().toLowerCase(Locale.ROOT);
            if (!isTargetInScope(host)) {
                return RequestToBeSentAction.continueWith(requestToBeSent);
            }

            String path = requestToBeSent.pathWithoutQuery().toLowerCase(Locale.ROOT);

            // 2. Comprehensive Session Shield: Drop all attempts to mess with auth state while crawling
            if (path.contains("logout") || path.contains("checklogin") || 
                path.contains("/login") || path.contains("forgotpassword")) {
                configService.logDiagnostics("[SessionShield] Blocked crawler exploratory packet to restricted authentication pathway: " + path);
                return RequestToBeSentAction.drop();
            }

            // 3. Forced Golden Session Injection: Override guest tokens with authenticated admin credentials
            String adminCookie = goldenAdminCookie.get();
            if (!adminCookie.isEmpty() && !isStaticResource(path)) {
                HttpRequest modifiedRequest = requestToBeSent;
                String existingCookieHeader = requestToBeSent.headerValue("Cookie");
                
                if (existingCookieHeader == null || existingCookieHeader.isBlank()) {
                    modifiedRequest = modifiedRequest.withAddedHeader("Cookie", "JSESSIONID=" + adminCookie);
                } else if (!existingCookieHeader.contains("JSESSIONID=" + adminCookie)) {
                    String cleanCookieHeader = replaceOrAppendJSessionId(existingCookieHeader, "JSESSIONID=" + adminCookie);
                    modifiedRequest = modifiedRequest.withUpdatedHeader(HttpHeader.httpHeader("Cookie", cleanCookieHeader));
                }
                return RequestToBeSentAction.continueWith(modifiedRequest);
            }
        } catch (Exception e) {
            configService.logDiagnostics("Error in secure request interception: " + e.getMessage());
        }
        return RequestToBeSentAction.continueWith(requestToBeSent);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
        // PERMANENTLY DISABLED BLIND COOKIE HARVESTING:
        // We explicitly decline to adopt Set-Cookie headers returned during exploratory crawling
        // to prevent unauthenticated guest sessions or failed fuzz responses from overriding our Golden Admin session!
        return ResponseReceivedAction.continueWith(responseReceived);
    }

    private boolean isTargetInScope(String host) {
        return host.equals("ofbiz") || host.equals("localhost") || host.equals("127.0.0.1") || host.endsWith(".ofbiz");
    }

    private boolean isStaticResource(String path) {
        return path.endsWith(".css") || path.endsWith(".js") || path.endsWith(".png") || path.endsWith(".gif") || path.endsWith(".jpg") || path.endsWith(".woff");
    }

    private String replaceOrAppendJSessionId(String existing, String goldenToken) {
        if (existing.contains("JSESSIONID=")) {
            return existing.replaceAll("JSESSIONID=[^;]+", goldenToken);
        }
        return existing + "; " + goldenToken;
    }
}