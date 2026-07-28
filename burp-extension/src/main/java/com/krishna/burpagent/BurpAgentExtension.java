package com.krishna.burpagent;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.AuditConfiguration;
import burp.api.montoya.scanner.BuiltInAuditConfiguration;
import burp.api.montoya.scanner.Crawl;
import burp.api.montoya.scanner.CrawlConfiguration;
import burp.api.montoya.scanner.ReportFormat;
import burp.api.montoya.scanner.audit.Audit;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;

public final class BurpAgentExtension implements BurpExtension {

    enum Phase { CRAWLING, AUDITING, COMPLETE, ERROR }

    static final class ScanJob {
        final String id;
        final String targetHost;
        volatile Crawl  crawl;
        volatile Audit  audit;
        volatile Phase  phase = Phase.CRAWLING;
        volatile String error = "";
        volatile int    crawlReqs = 0;
        volatile int    auditReqs = 0;
        volatile int    issueCount = 0;
        volatile String crawlStatus = "starting";
        volatile String auditStatus = "waiting";

        ScanJob(String id, String targetHost, Crawl crawl) {
            this.id = id; this.targetHost = targetHost; this.crawl = crawl;
        }
    }

    private MontoyaApi api;
    private String     token;
    private final ConcurrentHashMap<String, ScanJob> jobs = new ConcurrentHashMap<>();

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName("OFBiz Burp Agent Bridge");
        token = System.getenv().getOrDefault("BURP_BRIDGE_TOKEN", "");
        int port = Integer.parseInt(System.getenv().getOrDefault("BURP_BRIDGE_PORT", "1338"));
        if (token.length() < 8) throw new IllegalStateException("BURP_BRIDGE_TOKEN too short");
        try {
            HttpServer server = HttpServer.create(new InetSocketAddress("0.0.0.0", port), 0);
            server.createContext("/health",       x -> safe(x, this::health));
            server.createContext("/sitemap",      x -> safe(x, this::sitemap));
            server.createContext("/scan/start",   x -> safe(x, this::scanStart));
            server.createContext("/scan/audit",   x -> safe(x, this::startDirectAudit));
            server.createContext("/scan/status",  x -> safe(x, this::scanStatus));
            server.createContext("/scan/report",  x -> safe(x, this::scanReport));
            server.setExecutor(Executors.newCachedThreadPool());
            server.start();
            api.logging().logToOutput("Burp Agent Bridge listening on port " + port);
            api.extension().registerUnloadingHandler(() -> server.stop(0));
        } catch (IOException e) { throw new IllegalStateException(e); }
    }

    private @FunctionalInterface interface Handler { void handle(HttpExchange x) throws Exception; }
    private void safe(HttpExchange x, Handler h) {
        try { h.handle(x); }
        catch (Exception e) {
            api.logging().logToError("Handler error [" + x.getRequestURI() + "]: " + e);
            try { send(x, 500, "{\"error\":" + q(e.getClass().getSimpleName() + ": " + e.getMessage()) + "}"); }
            catch (IOException ignored) {}
        }
    }

    // ── /health ───────────────────────────────────────────────
    private void health(HttpExchange x) throws Exception {
        if (!authorized(x)) return;
        send(x, 200, "{\"ok\":true,\"version\":" + q(api.burpSuite().version().toString()) + "}");
    }

    // ── /sitemap  GET ?host=ofbiz ──────────────────────────────
    private void sitemap(HttpExchange x) throws Exception {
        if (!authorized(x)) return;
        String targetHost = query(x, "host", "ofbiz");
        List<String> items = new ArrayList<>();
        for (HttpRequestResponse rr : api.siteMap().requestResponses()) {
            if (!rr.hasResponse()) continue;
            if (!rr.httpService().host().equalsIgnoreCase(targetHost)) continue;
            int status = rr.response().statusCode();
            String method = rr.request().method();
            String url = rr.request().url();
            items.add(String.format("{\"method\":%s,\"url\":%s,\"status\":%d}", q(method), q(url), status));
        }
        send(x, 200, "{\"total\":" + items.size() + ",\"items\":[" + String.join(",", items) + "]}");
    }

    // ── /scan/start  POST ?url=...&host=... ──────────────────
    private void scanStart(HttpExchange x) throws Exception {
        if (!authorized(x)) return;
        if (!"POST".equalsIgnoreCase(x.getRequestMethod())) { send(x, 405, "{\"error\":\"POST required\"}"); return; }

        String rawUrl = query(x, "url", "https://ofbiz:8443/webtools/control/main");
        String host   = query(x, "host", "ofbiz");
        String[] seeds = rawUrl.split(",");

        Crawl crawl = api.scanner().startCrawl(CrawlConfiguration.crawlConfiguration(seeds));
        String id   = UUID.randomUUID().toString();
        ScanJob job = new ScanJob(id, host, crawl);
        job.crawlStatus = "crawling";
        jobs.put(id, job);

        new Thread(() -> crawlThenAudit(job), "scan-" + id).start();

        api.logging().logToOutput("Scan " + id + " started. URLs=" + rawUrl);
        send(x, 202, "{\"scanId\":" + q(id) + ",\"phase\":\"crawling\",\"url\":" + q(rawUrl) + "}");
    }

    // ── /scan/audit  POST ?host=ofbiz ── Directly audit current siteMap ──
    private void startDirectAudit(HttpExchange x) throws Exception {
        if (!authorized(x)) return;
        if (!"POST".equalsIgnoreCase(x.getRequestMethod())) { send(x, 405, "{\"error\":\"POST required\"}"); return; }

        String host = query(x, "host", "ofbiz");
        String id   = UUID.randomUUID().toString();
        ScanJob job = new ScanJob(id, host, null);
        job.phase   = Phase.AUDITING;
        job.crawlStatus = "bypassed";
        jobs.put(id, job);

        new Thread(() -> runDirectAudit(job), "audit-" + id).start();

        api.logging().logToOutput("Direct Audit " + id + " started for host=" + host);
        send(x, 202, "{\"scanId\":" + q(id) + ",\"phase\":\"auditing\",\"host\":" + q(host) + "}");
    }

    private void runDirectAudit(ScanJob job) {
        try {
            api.logging().logToOutput("[" + job.id + "] Collecting site-map items...");
            List<HttpRequestResponse> items = new ArrayList<>();
            for (HttpRequestResponse rr : api.siteMap().requestResponses()) {
                if (!rr.hasResponse()) continue;
                if (!rr.httpService().host().equalsIgnoreCase(job.targetHost)) continue;
                String path = rr.request().pathWithoutQuery();
                if (path.contains("logout") || path.contains("Logout")) continue;
                items.add(rr);
            }
            api.logging().logToOutput("[" + job.id + "] Direct Audit site-map items: " + items.size());

            if (items.isEmpty()) {
                job.phase = Phase.ERROR;
                job.error = "No items in site-map for host: " + job.targetHost;
                return;
            }

            Audit audit = api.scanner().startAudit(
                AuditConfiguration.auditConfiguration(BuiltInAuditConfiguration.LEGACY_ACTIVE_AUDIT_CHECKS)
            );
            for (HttpRequestResponse rr : items) {
                try { audit.addRequestResponse(rr); } catch (Exception ignored) {}
            }
            job.audit = audit;

            while (true) {
                Thread.sleep(10_000);
                try {
                    job.auditStatus = String.valueOf(audit.statusMessage());
                    job.auditReqs   = audit.requestCount();
                    job.issueCount  = audit.issues().size();
                } catch (Exception e) {
                    api.logging().logToError("Audit poll error: " + e);
                }
                api.logging().logToOutput("[" + job.id + "] audit: " + job.auditStatus + " issues=" + job.issueCount);
                if (job.auditStatus.toLowerCase(Locale.ROOT).matches(".*(finish|complet|done|idle).*")) break;
            }
            job.phase = Phase.COMPLETE;
            api.logging().logToOutput("[" + job.id + "] Direct Audit COMPLETE. Issues: " + job.issueCount);
        } catch (Exception e) {
            api.logging().logToError("[" + job.id + "] Direct Audit error: " + e);
            job.phase = Phase.ERROR;
            job.error = e.getMessage();
        }
    }

    private void crawlThenAudit(ScanJob job) {
        try {
            api.logging().logToOutput("[" + job.id + "] Crawl phase started");
            int stable = 0, lastReqs = -1;

            while (true) {
                Thread.sleep(8_000);
                try {
                    String msg = job.crawl.statusMessage();
                    job.crawlStatus = (msg != null && !msg.isBlank()) ? msg : "crawling";
                    job.crawlReqs   = job.crawl.requestCount();
                } catch (Exception e) {
                    api.logging().logToError("Crawl poll error: " + e);
                }
                api.logging().logToOutput("[" + job.id + "] crawl: " + job.crawlStatus + " reqs=" + job.crawlReqs);

                boolean done = job.crawlStatus.toLowerCase(Locale.ROOT)
                    .matches(".*(finish|complet|done|idle|cancel|stop|no more|error).*");
                if (done) break;

                if (job.crawlReqs == lastReqs) { if (++stable >= 12) break; }
                else { stable = 0; lastReqs = job.crawlReqs; }
            }

            api.logging().logToOutput("[" + job.id + "] Crawl done. Collecting site-map...");
            job.phase = Phase.AUDITING;
            job.auditStatus = "collecting";

            List<HttpRequestResponse> items = new ArrayList<>();
            try {
                for (HttpRequestResponse rr : api.siteMap().requestResponses()) {
                    if (!rr.hasResponse()) continue;
                    if (!rr.httpService().host().equalsIgnoreCase(job.targetHost)) continue;
                    String path = rr.request().pathWithoutQuery();
                    if (path.contains("logout") || path.contains("Logout")) continue;
                    items.add(rr);
                }
            } catch (Exception e) {
                api.logging().logToError("Site-map collect error: " + e);
            }
            api.logging().logToOutput("[" + job.id + "] Site-map items: " + items.size());

            if (items.isEmpty()) {
                job.phase = Phase.ERROR;
                job.error = "No items in site-map after crawl. Check OFBiz scope and credentials.";
                return;
            }

            Audit audit = api.scanner().startAudit(
                AuditConfiguration.auditConfiguration(BuiltInAuditConfiguration.LEGACY_ACTIVE_AUDIT_CHECKS)
            );
            for (HttpRequestResponse rr : items) {
                try { audit.addRequestResponse(rr); } catch (Exception ignored) {}
            }
            job.audit = audit;
            api.logging().logToOutput("[" + job.id + "] Audit started with " + items.size() + " items");

            while (true) {
                Thread.sleep(10_000);
                try {
                    job.auditStatus = String.valueOf(audit.statusMessage());
                    job.auditReqs   = audit.requestCount();
                    job.issueCount  = audit.issues().size();
                } catch (Exception e) {
                    api.logging().logToError("Audit poll error: " + e);
                }
                api.logging().logToOutput("[" + job.id + "] audit: " + job.auditStatus + " issues=" + job.issueCount);
                if (job.auditStatus.toLowerCase(Locale.ROOT).matches(".*(finish|complet|done|idle).*")) break;
            }
            job.phase = Phase.COMPLETE;
            api.logging().logToOutput("[" + job.id + "] COMPLETE. Issues: " + job.issueCount);

        } catch (Exception e) {
            api.logging().logToError("[" + job.id + "] Pipeline error: " + e);
            job.phase = Phase.ERROR;
            job.error = e.getMessage();
        }
    }

    // ── /scan/status  GET ?id=... ─────────────────────────────
    private void scanStatus(HttpExchange x) throws Exception {
        if (!authorized(x)) return;
        String id = query(x, "id", "");
        ScanJob job = jobs.get(id);
        if (job == null) { send(x, 404, "{\"error\":\"Unknown scanId: " + id + "\"}"); return; }

        boolean done = job.phase == Phase.COMPLETE || job.phase == Phase.ERROR;
        String json = String.format(
            "{\"phase\":%s,\"crawlStatus\":%s,\"auditStatus\":%s," +
            "\"crawlRequests\":%d,\"auditRequests\":%d,\"issues\":%d,\"complete\":%b,\"error\":%s}",
            q(job.phase.name().toLowerCase()), q(job.crawlStatus), q(job.auditStatus),
            job.crawlReqs, job.auditReqs, job.issueCount, done, q(job.error)
        );
        send(x, 200, json);
    }

    // ── /scan/report  POST ?id=... ────────────────────────────
    private void scanReport(HttpExchange x) throws Exception {
        if (!authorized(x)) return;
        if (!"POST".equalsIgnoreCase(x.getRequestMethod())) { send(x, 405, "{\"error\":\"POST required\"}"); return; }
        ScanJob job = jobs.get(query(x, "id", ""));
        if (job == null) { send(x, 404, "{\"error\":\"Unknown scan\"}"); return; }
        if (job.phase != Phase.COMPLETE) { send(x, 409, "{\"error\":\"Scan not complete yet (phase: " + job.phase + ")\"}"); return; }

        String artDir = System.getenv().getOrDefault("ARTIFACTS_DIR", "/artifacts");
        Path p = Path.of(artDir, "burp-vapt-report.html");
        Files.createDirectories(p.getParent());
        api.scanner().generateReport(new ArrayList<>(job.audit.issues()), ReportFormat.HTML, p);
        send(x, 200, "{\"path\":" + q(p.toString()) + ",\"issues\":" + job.issueCount + "}");
    }

    // ── Helpers ───────────────────────────────────────────────
    private boolean authorized(HttpExchange x) throws IOException {
        String got = x.getRequestHeaders().getFirst("Authorization");
        if (!("Bearer " + token).equals(got)) { send(x, 401, "{\"error\":\"Unauthorized\"}"); return false; }
        return true;
    }
    private static String query(HttpExchange x, String key, String def) {
        String raw = x.getRequestURI().getRawQuery();
        if (raw == null) return def;
        for (String p : raw.split("&")) {
            String[] kv = p.split("=", 2);
            if (kv[0].equals(key))
                return URLDecoder.decode(kv.length > 1 ? kv[1] : "", StandardCharsets.UTF_8);
        }
        return def;
    }
    private static void send(HttpExchange x, int code, String body) throws IOException {
        byte[] b = body.getBytes(StandardCharsets.UTF_8);
        x.getResponseHeaders().set("Content-Type", "application/json");
        x.sendResponseHeaders(code, b.length);
        x.getResponseBody().write(b);
        x.close();
    }
    private static String q(String s) {
        if (s == null) s = "";
        return "\"" + s.replace("\\","\\\\").replace("\"","\\\"").replace("\n","\\n").replace("\r","") + "\"";
    }
}
