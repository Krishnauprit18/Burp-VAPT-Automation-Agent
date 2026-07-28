package com.krishna.burpagent;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.AuditConfiguration;
import burp.api.montoya.scanner.BuiltInAuditConfiguration;
import burp.api.montoya.scanner.ReportFormat;
import burp.api.montoya.scanner.audit.Audit;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.net.InetSocketAddress;
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
    private MontoyaApi api;
    private HttpServer server;
    private final ConcurrentHashMap<String, Audit> audits = new ConcurrentHashMap<>();
    private String token;

    @Override public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName("OFBiz Burp Agent Bridge");
        token = System.getenv().getOrDefault("BURP_BRIDGE_TOKEN", "");
        int port = Integer.parseInt(System.getenv().getOrDefault("BURP_BRIDGE_PORT", "1338"));
        if (token.length() < 16) throw new IllegalStateException("BURP_BRIDGE_TOKEN must be at least 16 characters");
        try {
            server = HttpServer.create(new InetSocketAddress("0.0.0.0", port), 0);
            server.createContext("/health", this::health);
            server.createContext("/crawl/start", this::startCrawl);
            server.createContext("/crawl/status", this::crawlStatus);
            server.createContext("/site-map", this::siteMap);
            server.createContext("/audit/start", this::startAudit);
            server.createContext("/audit/status", this::auditStatus);
            server.createContext("/audit/report", this::auditReport);
            server.setExecutor(Executors.newCachedThreadPool());
            server.start();
            api.logging().logToOutput("Burp Agent Bridge listening on port " + port);
            api.extension().registerUnloadingHandler(() -> server.stop(0));
        } catch (IOException e) { throw new IllegalStateException(e); }
    }

    private final ConcurrentHashMap<String, burp.api.montoya.scanner.Crawl> crawls = new ConcurrentHashMap<>();

    private void startCrawl(HttpExchange x) throws IOException {
        if (!authorized(x)) return;
        if (!"POST".equalsIgnoreCase(x.getRequestMethod())) { send(x,405,"{\"error\":\"POST required\"}"); return; }
        String seedUrl = query(x, "url", "https://ofbiz:8443/webtools/control/checkLogin");
        try {
            burp.api.montoya.scanner.CrawlConfiguration cfg = burp.api.montoya.scanner.CrawlConfiguration.crawlConfiguration(seedUrl);
            burp.api.montoya.scanner.Crawl crawl = api.scanner().startCrawl(cfg);
            String id = UUID.randomUUID().toString();
            crawls.put(id, crawl);
            send(x, 202, "{\"crawlId\":" + q(id) + ",\"seedUrl\":" + q(seedUrl) + "}");
        } catch (Exception e) {
            send(x, 500, "{\"error\":" + q(e.toString()) + "}");
        }
    }

    private void crawlStatus(HttpExchange x) throws IOException {
        if (!authorized(x)) return;
        try {
            burp.api.montoya.scanner.Crawl c = crawls.get(query(x, "id", ""));
            if (c == null) { send(x, 404, "{\"error\":\"Unknown crawl\"}"); return; }
            String s = "";
            try { s = c.statusMessage(); } catch (Exception ignored) {}
            boolean complete = s != null && s.toLowerCase(Locale.ROOT)
                    .matches(".*(finished|complete|completed|done|ended|stopped).*");
            int req = 0, err = 0;
            try { req = c.requestCount(); } catch (Exception ignored) {}
            try { err = c.errorCount(); } catch (Exception ignored) {}
            send(x, 200, "{\"status\":" + q(s) + ",\"complete\":" + complete + ",\"requests\":" + req + ",\"errors\":" + err + "}");
        } catch (Exception e) {
            send(x, 500, "{\"error\":" + q(e.toString()) + "}");
        }
    }

    private void health(HttpExchange x) throws IOException {
        if (!authorized(x)) return;
        send(x, 200, "{\"ok\":true,\"version\":" + q(api.burpSuite().version().toString()) + "}");
    }

    private void siteMap(HttpExchange x) throws IOException {
        if (!authorized(x)) return;
        String host = query(x, "host", "ofbiz");
        List<HttpRequestResponse> items = filtered(host);
        StringBuilder b = new StringBuilder("{\"count\":").append(items.size()).append(",\"urls\":[");
        for (int i=0;i<items.size();i++) { if(i>0)b.append(','); b.append(q(items.get(i).request().url())); }
        send(x, 200, b.append("]}").toString());
    }

    private void startAudit(HttpExchange x) throws IOException {
        if (!authorized(x)) return;
        if (!"POST".equalsIgnoreCase(x.getRequestMethod())) { send(x,405,"{\"error\":\"POST required\"}"); return; }
        String host = query(x, "host", "ofbiz");
        List<HttpRequestResponse> items = filtered(host);
        if (items.isEmpty()) { send(x,409,"{\"error\":\"No captured in-scope traffic\"}"); return; }
        AuditConfiguration cfg = AuditConfiguration.auditConfiguration(BuiltInAuditConfiguration.LEGACY_ACTIVE_AUDIT_CHECKS);
        Audit audit = api.scanner().startAudit(cfg);
        for (HttpRequestResponse rr : items) audit.addRequestResponse(rr);
        String id = UUID.randomUUID().toString(); audits.put(id, audit);
        send(x, 202, "{\"auditId\":" + q(id) + ",\"queuedItems\":" + items.size() + "}");
    }

    private void auditStatus(HttpExchange x) throws IOException {
        if (!authorized(x)) return;
        try {
            Audit a = audits.get(query(x,"id",""));
            if (a == null) { send(x,404,"{\"error\":\"Unknown audit\"}"); return; }
            String s = "";
            try { s = a.statusMessage(); } catch (Exception ignored) {}
            boolean complete = s != null && s.toLowerCase(Locale.ROOT)
                    .matches(".*(finished|complete|completed|done|ended|stopped).*");
            int req = 0, err = 0, pts = 0, iss = 0;
            try { req = a.requestCount(); } catch (Exception ignored) {}
            try { err = a.errorCount(); } catch (Exception ignored) {}
            try { pts = a.insertionPointCount(); } catch (Exception ignored) {}
            try { iss = a.issues().size(); } catch (Exception ignored) {}
            send(x,200,"{\"status\":"+q(s)+",\"complete\":"+complete+",\"requests\":"+req+",\"errors\":"+err+",\"insertionPoints\":"+pts+",\"issues\":"+iss+"}");
        } catch (Exception e) {
            send(x, 500, "{\"error\":" + q(e.getMessage()) + "}");
        }
    }

    private void auditReport(HttpExchange x) throws IOException {
        if (!authorized(x)) return;
        try {
            Audit a = audits.get(query(x,"id",""));
            if (a == null) { send(x,404,"{\"error\":\"Unknown audit\"}"); return; }
            Path p = Path.of("/artifacts", "burp-active-scan-report.html");
            Files.createDirectories(p.getParent());
            List<AuditIssue> issues = a.issues();
            if (issues == null) issues = new ArrayList<>();
            try {
                api.scanner().generateReport(issues, ReportFormat.HTML, p);
            } catch (Throwable t) {
                // If HTML report generation fails on headless Montoya, create custom HTML summary
                StringBuilder html = new StringBuilder("<html><body><h1>Burp Active Scan Report</h1><p>Issues found: ").append(issues.size()).append("</p><ul>");
                for (AuditIssue issue : issues) {
                    html.append("<li><b>").append(issue.name()).append("</b> - ").append(issue.detail()).append("</li>");
                }
                html.append("</ul></body></html>");
                Files.writeString(p, html.toString());
            }
            send(x,200,"{\"path\":"+q(p.toString())+",\"issues\":"+issues.size()+"}");
        } catch (Exception e) {
            String err = e.getMessage() != null ? e.getMessage() : e.toString();
            send(x, 500, "{\"error\":" + q(err) + "}");
        }
    }

    private List<HttpRequestResponse> filtered(String host) {
        List<HttpRequestResponse> out = new ArrayList<>();
        for (HttpRequestResponse rr : api.siteMap().requestResponses()) {
            String url = rr.request().url();
            String path = rr.request().pathWithoutQuery();
            if (rr.hasResponse() && (host == null || host.isEmpty() || rr.httpService().host().equalsIgnoreCase(host))
                    && path.contains("/control/")
                    && !path.endsWith("/login") && !path.endsWith("/logout")) out.add(rr);
        }
        return out;
    }

    private boolean authorized(HttpExchange x) throws IOException {
        String got = x.getRequestHeaders().getFirst("Authorization");
        if (!("Bearer " + token).equals(got)) { send(x,401,"{\"error\":\"Unauthorized\"}"); return false; }
        return true;
    }
    private static String query(HttpExchange x,String key,String d) {
        String raw=x.getRequestURI().getRawQuery(); if(raw==null)return d;
        for(String p:raw.split("&")){String[]kv=p.split("=",2);if(kv[0].equals(key))return java.net.URLDecoder.decode(kv.length>1?kv[1]:"",StandardCharsets.UTF_8);}return d;
    }
    private static void send(HttpExchange x,int code,String body)throws IOException{byte[]b=body.getBytes(StandardCharsets.UTF_8);x.getResponseHeaders().set("Content-Type","application/json");x.sendResponseHeaders(code,b.length);x.getResponseBody().write(b);x.close();}
    private static String q(String s){if(s==null)s="";return "\""+s.replace("\\","\\\\").replace("\"","\\\"").replace("\n","\\n")+"\"";}
}
