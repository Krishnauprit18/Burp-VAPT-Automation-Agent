package com.krishna.burpagent.server;

import com.krishna.burpagent.service.ConfigurationService;
import com.krishna.burpagent.service.CrawlerSessionCoordinator;
import com.krishna.burpagent.service.OFBizAuthenticationService;
import com.krishna.burpagent.service.ReportAgent;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

public final class MontoyaBridgeServer {
    private final ConfigurationService config;
    private final OFBizAuthenticationService authenticationService;
    private final CrawlerSessionCoordinator sessionCoordinator;
    private final ReportAgent reportAgent;
    private final int port;
    private final String expectedToken;
    private ServerSocket serverSocket;
    private volatile boolean running = true;

    public MontoyaBridgeServer(
            ConfigurationService config,
            OFBizAuthenticationService authenticationService,
            CrawlerSessionCoordinator sessionCoordinator,
            ReportAgent reportAgent,
            int port,
            String expectedToken) {
        this.config = config;
        this.authenticationService = authenticationService;
        this.sessionCoordinator = sessionCoordinator;
        this.reportAgent = reportAgent;
        this.port = port;
        this.expectedToken = expectedToken;
    }

    public void start() throws IOException {
        serverSocket = new ServerSocket();
        serverSocket.bind(new InetSocketAddress("127.0.0.1", port));
        Thread serverThread = new Thread(this::listen, "native-burp-agent-bridge");
        serverThread.setDaemon(true);
        serverThread.start();
    }

    public void stop() {
        running = false;
        try {
            if (serverSocket != null) serverSocket.close();
        } catch (IOException ignored) {
        }
    }

    private void listen() {
        while (running) {
            try {
                Socket socket = serverSocket.accept();
                socket.setSoTimeout(15_000);
                Thread handler = new Thread(() -> handleClient(socket), "bridge-client-" + socket.getPort());
                handler.setDaemon(true);
                handler.start();
            } catch (IOException e) {
                if (running) config.logDiagnostics("Bridge accept error: " + e.getMessage());
            }
        }
    }

    private void handleClient(Socket socket) {
        try (socket;
             BufferedReader reader = new BufferedReader(
                     new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));
             OutputStream output = socket.getOutputStream()) {
            String requestLine = reader.readLine();
            if (requestLine == null) return;
            Map<String, String> headers = readHeaders(reader);
            if (!("Bearer " + expectedToken).equals(headers.get("authorization"))) {
                sendJson(output, 401, "Unauthorized", "{\"error\":\"Unauthorized\"}");
                return;
            }

            String[] requestParts = requestLine.split(" ");
            if (requestParts.length < 2) {
                sendJson(output, 400, "Bad Request", "{\"error\":\"Malformed request line\"}");
                return;
            }
            String method = requestParts[0];
            String fullPath = requestParts[1];
            int queryStart = fullPath.indexOf('?');
            String path = queryStart >= 0 ? fullPath.substring(0, queryStart) : fullPath;
            Map<String, String> parameters = parseQuery(queryStart >= 0 ? fullPath.substring(queryStart + 1) : "");

            if ("GET".equals(method) && "/health".equals(path)) {
                sendJson(output, 200, "OK",
                        "{\"ok\":true,\"mode\":\"montoya-session-and-report-bridge\"}");
            } else if ("POST".equals(method) && "/scan/prepare".equals(path)) {
                prepareScan(output);
            } else if ("POST".equals(method) && "/scan/report".equals(path)) {
                generateReports(parameters, output);
            } else {
                sendJson(output, 404, "Not Found", "{\"error\":\"Not Found\"}");
            }
        } catch (Exception e) {
            config.logDiagnostics("Bridge client error: " + e.getMessage());
        }
    }

    private synchronized void prepareScan(OutputStream output) throws IOException {
        try {
            config.applyProjectScope();
            sessionCoordinator.beginCredentialLogin();
            authenticationService.ensureAuthenticated();
            sendJson(output, 200, "OK",
                    "{\"ready\":true,\"authentication\":\"standby-session-verified\"}");
        } catch (Exception e) {
            sendJson(output, 500, "Internal Error", errorJson(e));
        }
    }

    private void generateReports(Map<String, String> parameters, OutputStream output) throws IOException {
        String taskId = parameters.get("id");
        if (taskId == null || !taskId.matches("[A-Za-z0-9._-]+")) {
            sendJson(output, 400, "Bad Request", "{\"error\":\"Invalid Burp task ID\"}");
            return;
        }
        try {
            ReportAgent.ReportResult reports = reportAgent.generate(taskId);
            String result = "{\"scanId\":\"" + json(taskId) + "\",\"issues\":"
                    + reports.issueCount() + ",\"html\":\"" + json(reports.html().toString())
                    + "\",\"xml\":\"" + json(reports.xml().toString()) + "\"}";
            sendJson(output, 200, "OK", result);
        } catch (Exception e) {
            sendJson(output, 500, "Internal Error", errorJson(e));
        }
    }

    private Map<String, String> readHeaders(BufferedReader reader) throws IOException {
        Map<String, String> headers = new HashMap<>();
        String line;
        while ((line = reader.readLine()) != null && !line.isEmpty()) {
            int separator = line.indexOf(':');
            if (separator > 0) {
                headers.put(line.substring(0, separator).trim().toLowerCase(Locale.ROOT),
                        line.substring(separator + 1).trim());
            }
        }
        return headers;
    }

    private Map<String, String> parseQuery(String query) {
        Map<String, String> values = new HashMap<>();
        if (query == null || query.isBlank()) return values;
        for (String pair : query.split("&")) {
            int separator = pair.indexOf('=');
            if (separator < 1) continue;
            values.put(
                    URLDecoder.decode(pair.substring(0, separator), StandardCharsets.UTF_8),
                    URLDecoder.decode(pair.substring(separator + 1), StandardCharsets.UTF_8)
            );
        }
        return values;
    }

    private void sendJson(OutputStream output, int status, String reason, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        String headers = "HTTP/1.1 " + status + " " + reason + "\r\n"
                + "Content-Type: application/json; charset=UTF-8\r\n"
                + "Content-Length: " + bytes.length + "\r\n"
                + "Connection: close\r\n\r\n";
        output.write(headers.getBytes(StandardCharsets.UTF_8));
        output.write(bytes);
        output.flush();
    }

    private String errorJson(Exception e) {
        String message = e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage();
        return "{\"error\":\"" + json(message) + "\"}";
    }

    private String json(String value) {
        if (value == null) return "";
        return value.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }
}
