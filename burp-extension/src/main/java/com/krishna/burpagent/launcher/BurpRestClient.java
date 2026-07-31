package com.krishna.burpagent.launcher;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

final class BurpRestClient {
    private static final Set<String> TERMINAL_STATUSES = Set.of("succeeded", "failed");
    private static final ObjectMapper JSON = new ObjectMapper();

    private final AgentConfiguration config;
    private final HttpClient httpClient;
    private final URI apiRoot;

    BurpRestClient(AgentConfiguration config) {
        this.config = config;
        this.apiRoot = apiRoot(config.burpRestApiUrl(), config.burpRestApiKey());
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(5))
                .build();
    }

    void awaitReady(Process burp) throws Exception {
        Instant deadline = Instant.now().plus(config.bridgeStartupTimeout());
        while (Instant.now().isBefore(deadline)) {
            if (isReady()) {
                System.out.println("[Burp REST agent] Burp Desktop REST API v0.1 is ready.");
                return;
            }
            if (!burp.isAlive()) {
                throw new IOException("Native Burp exited before its REST API became ready");
            }
            Thread.sleep(2_000);
        }
        throw new IOException("Burp REST API did not become ready before "
                + config.bridgeStartupTimeout());
    }

    boolean isReady() {
        try {
            HttpResponse<String> response = send("GET", "", null);
            return response.statusCode() == 200;
        } catch (Exception ignored) {
            return false;
        }
    }

    ScanTask startScan() throws Exception {
        String body = JSON.writeValueAsString(buildScanRequest(config));
        HttpResponse<String> response = send("POST", "scan", body);
        if (response.statusCode() != 201) {
            throw apiFailure("start Burp crawl-and-audit", response);
        }

        String location = response.headers().firstValue("Location")
                .orElseThrow(() -> new IOException(
                        "Burp REST API created a scan without a Location header"));
        String taskId = taskId(location);
        System.out.println("[Burp REST agent] Native crawl-and-audit task started: " + taskId);
        return new ScanTask(taskId, apiRoot.resolve("scan/" + taskId));
    }

    /**
     * Tries to attach to an already-running or paused Burp scan task by its
     * saved task ID, without issuing a new {@code POST /scan}.
     *
     * <p>Returns a populated {@link ScanTask} when the REST API confirms the
     * task is still known; returns empty when the task ID is stale (e.g. Burp
     * was fully quit and the project was never restored).
     */
    Optional<ScanTask> tryAttachExistingTask(String taskId) {
        try {
            URI statusUri = apiRoot.resolve("scan/" + taskId);
            HttpResponse<String> response = send(statusUri, "GET");
            if (response.statusCode() != 200) return Optional.empty();
            JsonNode root = JSON.readTree(response.body());
            String status = root.path("scan_status").asText("");
            if (status.isBlank()) return Optional.empty();
            System.out.println("[Burp REST agent] Attached to existing task " + taskId
                    + " (status: " + status + ")");
            return Optional.of(new ScanTask(taskId, statusUri));
        } catch (Exception ignored) {
            return Optional.empty();
        }
    }

    /**
     * Polls the Burp REST task until it reaches a terminal status.
     *
     * @param lastProgressRef updated on every poll so the shutdown hook in
     *                        {@link MasterPipelineAgent} can persist fresh state on Ctrl+C.
     */
    ScanProgress awaitCompletion(ScanTask task, Path runDirectory,
            AtomicReference<ScanProgress> lastProgressRef) throws Exception {
        String previousStatus = "";
        int previousProgress = -1;
        while (true) {
            HttpResponse<String> response = send(task.statusUri(), "GET");
            if (response.statusCode() != 200) {
                throw apiFailure("read Burp scan status", response);
            }

            JsonNode root = JSON.readTree(response.body());
            ScanProgress progress = ScanProgress.from(root);
            lastProgressRef.set(progress);   // always keep fresh for shutdown hook
            Files.writeString(
                    runDirectory.resolve("scan-status.json"),
                    JSON.writerWithDefaultPrettyPrinter().writeValueAsString(root),
                    StandardCharsets.UTF_8);

            if (!progress.status().equals(previousStatus)
                    || progress.percent() != previousProgress) {
                System.out.println("[Monitor agent] status=" + progress.status()
                        + ", progress=" + progress.percent() + "%"
                        + ", crawlRequests=" + progress.crawlRequests()
                        + ", uniqueLocations=" + progress.uniqueLocations()
                        + ", auditRequests=" + progress.auditRequests()
                        + ", issues=" + progress.issueEvents());
                previousStatus = progress.status();
                previousProgress = progress.percent();
            }

            if (TERMINAL_STATUSES.contains(progress.status())) {
                if ("failed".equals(progress.status())) {
                    throw new IOException("Burp scan failed"
                            + optionalDetail(progress.message())
                            + optionalErrorCode(progress.errorCode()));
                }
                return progress;
            }
            Thread.sleep(config.pollInterval().toMillis());
        }
    }

    static ObjectNode buildScanRequest(AgentConfiguration config) {
        ObjectNode scan = JSON.createObjectNode();
        scan.putArray("urls").add(config.targetUrl());
        scan.put("protocol_option", "specified");

        // 1. Application Logins
        ObjectNode login = scan.putArray("application_logins").addObject();
        login.put("type", "UsernameAndPasswordLogin");
        login.put("label", "OFBiz administrator");

        java.nio.file.Path configDir = config.projectRoot().resolve("config");
        java.nio.file.Path credPath = configDir.resolve("ofbiz-credConfig.json");
        boolean credsLoaded = false;
        if (java.nio.file.Files.isRegularFile(credPath)) {
            try {
                String credJson = java.nio.file.Files.readString(credPath, java.nio.charset.StandardCharsets.UTF_8);
                com.fasterxml.jackson.databind.JsonNode credNode = JSON.readTree(credJson);
                com.fasterxml.jackson.databind.JsonNode credentials = credNode.path("application_login").path("credentials");
                if (credentials.isArray() && credentials.size() > 0) {
                    com.fasterxml.jackson.databind.JsonNode firstCred = credentials.get(0);
                    login.put("username", firstCred.path("username").asText(config.username()));
                    login.put("password", firstCred.path("password").asText(config.password()));
                    credsLoaded = true;
                    System.out.println("[Master agent] Loaded credentials from config/ofbiz-credConfig.json");
                }
            } catch (Exception e) {
                System.err.println("[Master agent] Failed to parse ofbiz-credConfig.json: " + e.getMessage());
            }
        }
        if (!credsLoaded) {
            login.put("username", config.username());
            login.put("password", config.password());
        }

        // 2. Scan Configurations
        ArrayNode scanConfigs = scan.putArray("scan_configurations");

        String[] configFiles = {"ofbiz-scanConfig.json", "ofbiz-scandetails-config.json"};
        for (String file : configFiles) {
            java.nio.file.Path path = configDir.resolve(file);
            if (java.nio.file.Files.isRegularFile(path)) {
                try {
                    String content = java.nio.file.Files.readString(path, java.nio.charset.StandardCharsets.UTF_8);
                    scanConfigs.addObject()
                            .put("type", "CustomConfiguration")
                            .put("config", content);
                    System.out.println("[Master agent] Loaded " + file + " into scan_configurations.");
                } catch (Exception e) {
                    System.err.println("[Master agent] Failed to load " + file + ": " + e.getMessage());
                }
            }
        }

        return scan;
    }

    private HttpResponse<String> send(String method, String relativePath, String body)
            throws IOException, InterruptedException {
        return send(apiRoot.resolve(relativePath), method, body);
    }

    private HttpResponse<String> send(URI uri, String method)
            throws IOException, InterruptedException {
        return send(uri, method, null);
    }

    private HttpResponse<String> send(URI uri, String method, String body)
            throws IOException, InterruptedException {
        HttpRequest.Builder request = HttpRequest.newBuilder(uri)
                .header("Accept", "application/json");
        if (body == null) {
            request.method(method, HttpRequest.BodyPublishers.noBody());
        } else {
            request.header("Content-Type", "application/json")
                    .method(method, HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8));
        }
        return httpClient.send(
                request.build(),
                HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
    }

    private IOException apiFailure(String action, HttpResponse<String> response) {
        String detail = response.body() == null ? "" : response.body().replaceAll("\\s+", " ").trim();
        if (detail.length() > 500) detail = detail.substring(0, 500) + "...";
        return new IOException("Could not " + action + " (HTTP " + response.statusCode() + ")"
                + optionalDetail(detail));
    }

    private static URI apiRoot(String rawBaseUrl, String apiKey) {
        URI base = URI.create(rawBaseUrl);
        String host = base.getHost() == null ? "" : base.getHost().toLowerCase(Locale.ROOT);
        if (!"http".equalsIgnoreCase(base.getScheme())
                || !(host.equals("127.0.0.1") || host.equals("localhost") || host.equals("::1"))) {
            throw new IllegalArgumentException(
                    "BURP_REST_API_URL must be an HTTP loopback URL");
        }
        if (base.getPort() < 1) {
            throw new IllegalArgumentException("BURP_REST_API_URL must include the REST API port");
        }
        String normalized = rawBaseUrl.endsWith("/")
                ? rawBaseUrl.substring(0, rawBaseUrl.length() - 1)
                : rawBaseUrl;
        return URI.create(normalized + "/" + apiKey + "/v0.1/");
    }

    private static String taskId(String location) throws IOException {
        String path = URI.create(location).getPath();
        if (path == null || path.isBlank()) {
            throw new IOException("Burp returned an invalid scan Location header");
        }
        String[] segments = path.split("/");
        String candidate = segments[segments.length - 1];
        if (!candidate.matches("[A-Za-z0-9._-]+")) {
            throw new IOException("Burp returned an invalid scan task identifier");
        }
        return candidate;
    }

    private static String optionalDetail(String value) {
        return value == null || value.isBlank() ? "" : ": " + value;
    }

    private static String optionalErrorCode(Integer value) {
        return value == null ? "" : " (error code " + value + ")";
    }

    record ScanTask(String id, URI statusUri) {}

    record ScanProgress(
            String taskId,
            String status,
            String message,
            Integer errorCode,
            int percent,
            int crawlRequests,
            int uniqueLocations,
            int auditRequests,
            int issueEvents) {

        static ScanProgress from(JsonNode root) throws IOException {
            String taskId = requiredText(root, "task_id");
            String status = requiredText(root, "scan_status");
            JsonNode metrics = root.path("scan_metrics");
            if (!metrics.isObject()) {
                throw new IOException("Burp scan response did not contain scan_metrics");
            }
            return new ScanProgress(
                    taskId,
                    status,
                    root.path("message").asText(""),
                    root.path("error_code").isIntegralNumber()
                            ? root.path("error_code").intValue() : null,
                    metrics.path("crawl_and_audit_progress").asInt(),
                    metrics.path("crawl_requests_made").asInt(),
                    metrics.path("crawl_unique_locations_visited").asInt(),
                    metrics.path("audit_requests_made").asInt(),
                    metrics.path("issue_events").asInt());
        }

        private static String requiredText(JsonNode root, String field) throws IOException {
            String value = root.path(field).asText("");
            if (value.isBlank()) {
                throw new IOException("Burp scan response did not contain " + field);
            }
            return value;
        }
    }
}
