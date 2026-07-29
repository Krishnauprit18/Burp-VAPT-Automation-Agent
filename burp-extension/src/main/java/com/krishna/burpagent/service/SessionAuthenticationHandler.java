package com.krishna.burpagent.service;

import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.util.Locale;

public class SessionAuthenticationHandler implements HttpHandler {
    private final ConfigurationService configService;
    private final OFBizAuthenticationService authenticationService;
    private final CrawlerSessionCoordinator sessionCoordinator;
    private final String targetHost;
    private final int targetPort;

    public SessionAuthenticationHandler(
            ConfigurationService configService,
            OFBizAuthenticationService authenticationService,
            CrawlerSessionCoordinator sessionCoordinator) {
        this.configService = configService;
        this.authenticationService = authenticationService;
        this.sessionCoordinator = sessionCoordinator;
        this.targetHost = configService.targetHost().toLowerCase(Locale.ROOT);
        this.targetPort = configService.targetPort();
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
        try {
            String host = requestToBeSent.httpService().host().toLowerCase(Locale.ROOT);
            int port = requestToBeSent.httpService().port();
            String path = requestToBeSent.pathWithoutQuery().toLowerCase(Locale.ROOT);
            if (!isTargetService(host, port)) {
                return RequestToBeSentAction.continueWith(requestToBeSent);
            }
            if (!configService.isAllowedPath(path)) {
                configService.logDiagnostics(
                        "[Scope agent] Blocked explicitly excluded Ecommerce request: " + path);
                return RequestToBeSentAction.drop();
            }

            if (configService.isLogoutPath(path)) {
                configService.logDiagnostics(
                        "[Session agent] Blocked crawler request to a logout endpoint: " + path);
                return RequestToBeSentAction.drop();
            }

            if (requestToBeSent.toolSource().isFromTool(ToolType.SCANNER)
                    && configService.isCrawlerNavigationTrap(path)) {
                configService.logDiagnostics(
                        "[Crawl guard] Blocked state-changing OFBiz utility navigation: " + path);
                return RequestToBeSentAction.drop();
            }

            if (configService.isLoginPath(path)) {
                if ("POST".equalsIgnoreCase(requestToBeSent.method())) {
                    logCredentialSubmissionShape(requestToBeSent);
                }
                return RequestToBeSentAction.continueWith(requestToBeSent);
            }

            if (isStaticResource(path)) {
                return RequestToBeSentAction.continueWith(requestToBeSent);
            }

            // OFBiz web applications have independent servlet sessions. The
            // WebTools standby session must never replace a session created by
            // externalLoginKey for Accounting, Party Manager, Catalog, etc.
            if (!configService.usesPrimaryApplicationSession(path)) {
                return RequestToBeSentAction.continueWith(requestToBeSent);
            }

            String sessionId = sessionCoordinator.shouldInjectAgentSession()
                    ? authenticationService.currentSessionId()
                    : sessionCoordinator.burpSessionId();
            if (!sessionId.isEmpty()) {
                HttpRequest modifiedRequest = requestToBeSent;
                String existingCookieHeader = requestToBeSent.headerValue("Cookie");
                
                if (existingCookieHeader == null || existingCookieHeader.isBlank()) {
                    modifiedRequest = modifiedRequest.withAddedHeader("Cookie", "JSESSIONID=" + sessionId);
                } else if (!existingCookieHeader.contains("JSESSIONID=" + sessionId)) {
                    String cleanCookieHeader = replaceOrAppendJSessionId(
                            existingCookieHeader, "JSESSIONID=" + sessionId);
                    modifiedRequest = modifiedRequest.withUpdatedHeader(HttpHeader.httpHeader("Cookie", cleanCookieHeader));
                }
                return RequestToBeSentAction.continueWith(modifiedRequest);
            }
        } catch (Exception e) {
            configService.logDiagnostics(
                    "[Session agent] Request interception failed; request was left unchanged: "
                            + e.getMessage());
            return RequestToBeSentAction.continueWith(requestToBeSent);
        }
        return RequestToBeSentAction.continueWith(requestToBeSent);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
        try {
            String host = responseReceived.initiatingRequest().httpService().host().toLowerCase(Locale.ROOT);
            int port = responseReceived.initiatingRequest().httpService().port();
            String path = responseReceived.initiatingRequest().pathWithoutQuery().toLowerCase(Locale.ROOT);
            if (!isTargetService(host, port)
                    || !configService.isAllowedPath(path)
                    || configService.isLogoutPath(path)
                    || !configService.usesPrimaryApplicationSession(path)) {
                return ResponseReceivedAction.continueWith(responseReceived);
            }

            String location = responseReceived.headerValue("Location");
            String body = responseReceived.bodyToString().toLowerCase(Locale.ROOT);
            boolean redirectedToLogin = location != null
                    && (location.toLowerCase(Locale.ROOT).contains("login")
                    || location.toLowerCase(Locale.ROOT).contains("checklogin"));
            boolean loginForm = body.contains("name=\"username\"") && body.contains("name=\"password\"");
            boolean unauthenticated = responseReceived.statusCode() == 401
                    || redirectedToLogin || loginForm;
            boolean burpLoginSubmission = configService.isLoginPath(path)
                    && "POST".equalsIgnoreCase(responseReceived.initiatingRequest().method());
            boolean configuredCredentialSubmission = burpLoginSubmission
                    && hasConfiguredCredentials(responseReceived.initiatingRequest());

            if (configuredCredentialSubmission && !unauthenticated) {
                String issuedSession = value(responseReceived.cookieValue("JSESSIONID"));
                if (issuedSession.isBlank()) {
                    issuedSession = extractJSessionId(
                            responseReceived.initiatingRequest().headerValue("Cookie"));
                }
                if (!issuedSession.isBlank()
                        && sessionCoordinator.establishBurpCredentialSession(issuedSession)) {
                    configService.logDiagnostics(
                            "[Session agent] Burp crawler authenticated using configured credentials.");
                }
            } else if ((configuredCredentialSubmission && unauthenticated)
                    || (!burpLoginSubmission && unauthenticated
                    && sessionCoordinator.burpCredentialLoginEstablished())) {
                activateRecovery(path);
            } else if (!burpLoginSubmission && unauthenticated
                    && sessionCoordinator.shouldInjectAgentSession()) {
                refreshRecoverySession(responseReceived, path);
            }
        } catch (Exception e) {
            configService.logDiagnostics("[Session agent] Response inspection failed: " + e.getMessage());
        }
        return ResponseReceivedAction.continueWith(responseReceived);
    }

    private void logCredentialSubmissionShape(HttpRequest request) {
        String username = request.parameterValue("USERNAME");
        String password = request.parameterValue("PASSWORD");
        String cookie = request.headerValue("Cookie");
        configService.logDiagnostics(
                "[Session agent] Observed Burp login submission: "
                        + "USERNAME field=" + (username != null)
                        + ", username matches=" + configService.ofbizUsername().equals(username)
                        + ", PASSWORD field=" + (password != null)
                        + ", password matches=" + configService.ofbizPassword().equals(password)
                        + ", JSESSIONID present=" + (cookie != null && cookie.contains("JSESSIONID="))
                        + ". Values were not logged.");
    }

    private boolean hasConfiguredCredentials(HttpRequest request) {
        return configService.ofbizUsername().equals(request.parameterValue("USERNAME"))
                && configService.ofbizPassword().equals(request.parameterValue("PASSWORD"));
    }

    private String value(String value) {
        return value == null ? "" : value;
    }

    private void activateRecovery(String path) {
        authenticationService.ensureAuthenticated();
        if (sessionCoordinator.activateAgentRecoverySession()) {
            String message = "[Session agent] Burp authentication was lost at " + path
                    + "; verified agent JSESSIONID will be injected into subsequent crawler requests.";
            configService.logDiagnostics(message);
        }
    }

    private void refreshRecoverySession(HttpResponseReceived responseReceived, String path) {
        String observed = extractJSessionId(
                responseReceived.initiatingRequest().headerValue("Cookie"));
        authenticationService.requestRefresh(
                observed,
                "Agent recovery session was rejected at " + path);
        authenticationService.ensureAuthenticated();
        String message = "[Session agent] Agent recovery JSESSIONID was renewed after rejection at "
                + path + ".";
        configService.logDiagnostics(message);
    }

    private boolean isTargetService(String host, int port) {
        return host.equals(targetHost) && port == targetPort;
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

    private String extractJSessionId(String cookieHeader) {
        if (cookieHeader == null) return "";
        for (String part : cookieHeader.split(";")) {
            String value = part.trim();
            if (value.startsWith("JSESSIONID=")) {
                return value.substring("JSESSIONID=".length()).trim();
            }
        }
        return "";
    }
}
