package com.krishna.burpagent.launcher;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;

final class MontoyaBridgeClient {
    private final AgentConfiguration config;
    private final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();
    private final String baseUrl;

    MontoyaBridgeClient(AgentConfiguration config) {
        this.config = config;
        this.baseUrl = "http://127.0.0.1:" + config.bridgePort();
    }

    boolean isHealthy() {
        try {
            HttpResponse<String> response = send("GET", "/health", Duration.ofSeconds(3));
            return response.statusCode() == 200;
        } catch (Exception ignored) {
            return false;
        }
    }

    void awaitHealthy(Process burp) throws Exception {
        Instant deadline = Instant.now().plus(config.bridgeStartupTimeout());
        while (Instant.now().isBefore(deadline)) {
            if (isHealthy()) {
                System.out.println("[Burp agent] Montoya extension bridge is ready.");
                return;
            }
            if (!burp.isAlive()) {
                throw new IOException("Native Burp exited before the extension bridge became ready");
            }
            Thread.sleep(2_000);
        }
        throw new IOException("Burp extension bridge did not become ready before " + config.bridgeStartupTimeout());
    }

    void prepareScan() throws Exception {
        HttpResponse<String> response = send("POST", "/scan/prepare", Duration.ofMinutes(2));
        requireSuccess(response, "prepare Montoya authentication and session recovery");
        System.out.println("[Session agent] Standby OFBiz session and Montoya recovery are ready.");
    }

    String generateReports(String scanId, Path runDirectory) throws Exception {
        HttpResponse<String> response = send(
                "POST", "/scan/report?id=" + encode(scanId), Duration.ofMinutes(5));
        requireSuccess(response, "generate reports");
        Files.writeString(runDirectory.resolve("run-summary.json"), response.body(), StandardCharsets.UTF_8);
        return response.body();
    }

    private HttpResponse<String> send(String method, String path, Duration timeout)
            throws IOException, InterruptedException {
        HttpRequest.Builder request = HttpRequest.newBuilder(URI.create(baseUrl + path))
                .timeout(timeout)
                .header("Authorization", "Bearer " + config.bridgeToken());
        request.method(method, HttpRequest.BodyPublishers.noBody());
        return http.send(request.build(), HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
    }

    private void requireSuccess(HttpResponse<String> response, String operation) throws IOException {
        if (response.statusCode() < 200 || response.statusCode() >= 300) {
            throw new IOException("Could not " + operation + " (HTTP " + response.statusCode() + "): " + response.body());
        }
    }

    private String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }
}
