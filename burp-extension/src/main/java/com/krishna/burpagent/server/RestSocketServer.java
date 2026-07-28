package com.krishna.burpagent.server;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.scanner.ReportFormat;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import com.krishna.burpagent.model.ScanJob;
import com.krishna.burpagent.service.ConfigurationService;
import com.krishna.burpagent.service.ScanEngineService;

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;

public class RestSocketServer {
    private final MontoyaApi api;
    private final ConfigurationService configService;
    private final ScanEngineService scanEngine;
    private final int port;
    private final String expectedToken;
    private ServerSocket serverSocket;
    private volatile boolean running = true;

    public RestSocketServer(MontoyaApi api, ConfigurationService configService, ScanEngineService scanEngine, int port, String expectedToken) {
        this.api = api;
        this.configService = configService;
        this.scanEngine = scanEngine;
        this.port = port;
        this.expectedToken = expectedToken;
    }

    public void start() throws IOException {
        this.serverSocket = new ServerSocket();
        this.serverSocket.bind(new InetSocketAddress("127.0.0.1", port));
        Thread serverThread = new Thread(this::listen, "RestSocketServer-Thread");
        serverThread.setDaemon(true);
        serverThread.start();
    }

    public void stop() {
        this.running = false;
        try { if (serverSocket != null) serverSocket.close(); } catch (IOException ignored) {}
    }

    private void listen() {
        while (running) {
            try {
                Socket socket = serverSocket.accept();
                socket.setSoTimeout(10000);
                new Thread(() -> handleClient(socket)).start();
            } catch (IOException e) {
                if (running) configService.logDiagnostics("Socket Server accept exception: " + e.getMessage());
            }
        }
    }

    private void handleClient(Socket socket) {
        try (InputStream in = socket.getInputStream(); OutputStream out = socket.getOutputStream()) {
            BufferedReader reader = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8));
            String requestLine = reader.readLine();
            if (requestLine == null) return;

            Map<String, String> headers = new HashMap<>();
            String line;
            while ((line = reader.readLine()) != null && !line.isEmpty()) {
                int idx = line.indexOf(":");
                if (idx != -1) headers.put(line.substring(0, idx).trim().toLowerCase(Locale.ROOT), line.substring(idx + 1).trim());
            }

            String auth = headers.get("authorization");
            if (auth == null || !auth.equals("Bearer " + expectedToken)) {
                sendResponse(out, 401, "Unauthorized", "{\"error\":\"Unauthorized\"}", "application/json");
                return;
            }

            String[] parts = requestLine.split(" ");
            if (parts.length < 2) return;
            String method = parts[0];
            String fullPath = parts[1];

            String path = fullPath.contains("?") ? fullPath.substring(0, fullPath.indexOf("?")) : fullPath;
            String query = fullPath.contains("?") ? fullPath.substring(fullPath.indexOf("?") + 1) : "";
            Map<String, String> params = parseQuery(query);

            if (method.equals("GET") && path.equals("/health")) {
                sendResponse(out, 200, "OK", "{\"ok\":true,\"status\":\"Operational\",\"mode\":\"Crawl and Audit\",\"version\":\"" + api.burpSuite().version().edition() + " " + api.burpSuite().version().build() + "\"}", "application/json");
            } else if (method.equals("POST") && path.equals("/scan/start")) {
                handleScanStart(reader, headers, out);
            } else if (method.equals("GET") && path.equals("/scan/status")) {
                handleScanStatus(params, out);
            } else if (method.equals("GET") && path.equals("/scan/report")) {
                handleScanReport(params, out);
            } else if (method.equals("GET") && path.equals("/sitemap")) {
                handleSitemap(params, out);
            } else {
                sendResponse(out, 404, "Not Found", "{\"error\":\"Not Found\"}", "application/json");
            }
        } catch (Exception e) {
            configService.logDiagnostics("Client handler error: " + e.getMessage());
        } finally {
            try { socket.close(); } catch (IOException ignored) {}
        }
    }

    private void handleScanStart(BufferedReader reader, Map<String, String> headers, OutputStream out) throws IOException {
        int contentLen = Integer.parseInt(headers.getOrDefault("content-length", "0"));
        char[] bodyChars = new char[contentLen];
        int read = reader.read(bodyChars, 0, contentLen);
        String body = new String(bodyChars, 0, read);

        String rawUrl = extractJsonString(body, "url");
        String host = extractJsonString(body, "host");
        if (host == null || host.isBlank()) host = "ofbiz";

        try {
            ScanJob job = scanEngine.launchCrawlPipeline(rawUrl, host);
            sendResponse(out, 200, "OK", "{\"scanId\":\"" + job.getId() + "\",\"phase\":\"" + job.getPhaseString() + "\"}", "application/json");
        } catch (IllegalStateException e) {
            sendResponse(out, 409, "Conflict", "{\"error\":\"" + e.getMessage() + "\"}", "application/json");
        } catch (IllegalArgumentException e) {
            sendResponse(out, 400, "Bad Request", "{\"error\":\"" + e.getMessage() + "\"}", "application/json");
        }
    }

    private void handleScanStatus(Map<String, String> params, OutputStream out) throws IOException {
        String id = params.get("id");
        if (id == null) {
            sendResponse(out, 400, "Bad Request", "{\"error\":\"Missing id parameter\"}", "application/json");
            return;
        }
        ScanJob job = scanEngine.getJob(id);
        if (job == null) {
            sendResponse(out, 404, "Not Found", "{\"error\":\"Job not found\"}", "application/json");
            return;
        }
        sendResponse(out, 200, "OK", job.toJsonStatus(), "application/json");
    }

    private void handleScanReport(Map<String, String> params, OutputStream out) throws IOException {
        String id = params.get("id");
        String formatParam = params.getOrDefault("format", "HTML").toUpperCase(Locale.ROOT);
        
        if (id == null) {
            sendResponse(out, 400, "Bad Request", "{\"error\":\"Missing scan id parameter\"}", "application/json");
            return;
        }
        ScanJob job = scanEngine.getJob(id);
        if (job == null) {
            sendResponse(out, 404, "Not Found", "{\"error\":\"Job not found\"}", "application/json");
            return;
        }

        try {
            List<AuditIssue> issues = api.siteMap().issues();
            ReportFormat reportFormat = formatParam.equals("XML") ? ReportFormat.XML : ReportFormat.HTML;
            
            Path tempReportFile = Files.createTempFile("ofbiz_vapt_report_", "." + reportFormat.name().toLowerCase(Locale.ROOT));
            api.scanner().generateReport(issues, reportFormat, tempReportFile);
            
            byte[] reportBytes = Files.readAllBytes(tempReportFile);
            Files.deleteIfExists(tempReportFile);

            String contentType = reportFormat == ReportFormat.XML ? "application/xml" : "text/html; charset=UTF-8";
            sendBytesResponse(out, 200, "OK", reportBytes, contentType);
            api.logging().logToOutput("[Report] Generated and exported " + reportFormat.name() + " security report containing " + issues.size() + " issues.");
        } catch (Exception e) {
            sendResponse(out, 500, "Internal Error", "{\"error\":\"Report generation failure: " + e.getMessage() + "\"}", "application/json");
        }
    }

    private void handleSitemap(Map<String, String> params, OutputStream out) throws IOException {
        String hostParam = params.getOrDefault("host", "ofbiz");
        List<String> urls = new ArrayList<>();
        api.siteMap().requestResponses().forEach(item -> {
            if (item.request() != null && item.request().httpService() != null) {
                if (item.request().httpService().host().equalsIgnoreCase(hostParam)) {
                    urls.add("{\"url\":\"" + item.request().url().replace("\"", "\\\"") + "\",\"status\":" + (item.response() != null ? item.response().statusCode() : 0) + "}");
                }
            }
        });
        sendResponse(out, 200, "OK", "{\"count\":" + urls.size() + ",\"items\":[" + String.join(",", urls) + "]}", "application/json");
    }

    private String extractJsonString(String json, String key) {
        String search = "\"" + key + "\":";
        int idx = json.indexOf(search);
        if (idx == -1) return null;
        int start = json.indexOf("\"", idx + search.length());
        if (start == -1) return null;
        int end = json.indexOf("\"", start + 1);
        if (end == -1) return null;
        return json.substring(start + 1, end);
    }

    private Map<String, String> parseQuery(String query) {
        Map<String, String> map = new HashMap<>();
        if (query == null || query.isEmpty()) return map;
        for (String pair : query.split("&")) {
            int idx = pair.indexOf("=");
            if (idx > 0 && idx < pair.length() - 1) {
                try { map.put(URLDecoder.decode(pair.substring(0, idx), "UTF-8"), URLDecoder.decode(pair.substring(idx + 1), "UTF-8")); } catch (Exception ignored) {}
            }
        }
        return map;
    }

    private void sendResponse(OutputStream out, int status, String reason, String body, String contentType) throws IOException {
        byte[] bodyBytes = body.getBytes(StandardCharsets.UTF_8);
        sendBytesResponse(out, status, reason, bodyBytes, contentType);
    }

    private void sendBytesResponse(OutputStream out, int status, String reason, byte[] bodyBytes, String contentType) throws IOException {
        String headers = "HTTP/1.1 " + status + " " + reason + "\r\n" +
                "Content-Type: " + contentType + "\r\n" +
                "Content-Length: " + bodyBytes.length + "\r\n" +
                "Connection: close\r\n\r\n";
        out.write(headers.getBytes(StandardCharsets.UTF_8));
        out.write(bodyBytes);
        out.flush();
    }
}