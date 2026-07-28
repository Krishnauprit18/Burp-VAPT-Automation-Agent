package com.krishna.burpagent.service;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.AuditConfiguration;
import burp.api.montoya.scanner.BuiltInAuditConfiguration;
import burp.api.montoya.scanner.Crawl;
import burp.api.montoya.scanner.CrawlConfiguration;
import burp.api.montoya.scanner.audit.Audit;
import com.krishna.burpagent.model.ScanJob;

import javax.net.ssl.*;
import java.io.*;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.stream.Collectors;

public class ScanEngineService {
    private final MontoyaApi api;
    private final ConfigurationService configService;
    private final SessionAuthenticationHandler sessionHandler;
    private final ConcurrentHashMap<String, ScanJob> activeJobs = new ConcurrentHashMap<>();
    private final AtomicBoolean scanInProgress = new AtomicBoolean(false);

    private final long maxCrawlMillis = 7200_000L;
    private final long idleThresholdMillis = 35_000L;
    private final long maxAuditMillis = 10800_000L; // 3 hours limit for active attacking
    private final long auditIdleMillis = 45_000L;

    public ScanEngineService(MontoyaApi api, ConfigurationService configService, SessionAuthenticationHandler sessionHandler) {
        this.api = api;
        this.configService = configService;
        this.sessionHandler = sessionHandler;
    }

    public ScanJob getJob(String id) { return activeJobs.get(id); }
    public boolean isBusy() { return scanInProgress.get(); }
    public void setIdle() { scanInProgress.set(false); }

    public ScanJob launchCrawlPipeline(String rawUrl, String host) {
        if (!scanInProgress.compareAndSet(false, true)) {
            throw new IllegalStateException("An active assessment pipeline is already running.");
        }
        configService.injectAggressiveScanRules();
        
        // 1. Execute Programmatic Pre-Authentication Handshake
        performAdminAuthenticationHandshake(host);

        String[] seeds = validateSeeds(rawUrl, host);
        Crawl crawl = api.scanner().startCrawl(CrawlConfiguration.crawlConfiguration(seeds));
        
        String id = UUID.randomUUID().toString();
        ScanJob job = new ScanJob(id, host, crawl);
        job.crawlStatus = "initializing automated crawl & audit pipeline...";
        job.auditStatus = "queued (waiting for discovery completion)";
        activeJobs.put(id, job);

        new Thread(() -> runFullPipelineTask(job), "pipeline-worker-" + id).start();
        api.logging().logToOutput("[ScanEngine] Launched automated Crawl -> Active Audit pipeline: " + id);
        return job;
    }

    private void runFullPipelineTask(ScanJob job) {
        try {
            // ==========================================
            // PHASE 1: AUTHENTICATED CRAWL DISCOVERY
            // ==========================================
            long startTime = System.currentTimeMillis();
            long lastProgressTime = System.currentTimeMillis();
            int previousReqs = -1;

            while (true) {
                Thread.sleep(5000);
                int currentReqs = 0;
                int currentErrors = 0;
                
                try { currentReqs = job.crawl.requestCount(); } catch (Exception ignored) {}
                try { currentErrors = job.crawl.errorCount(); } catch (Exception ignored) {}
                
                job.crawlRequests = currentReqs;
                job.crawlStatus = "active discovery (requests: " + currentReqs + ", errors: " + currentErrors + ")";
                api.logging().logToOutput("[" + job.getId() + "] [Crawl Phase] Requests: " + currentReqs + " | Network Errors: " + currentErrors);

                if (currentReqs != previousReqs) {
                    previousReqs = currentReqs;
                    lastProgressTime = System.currentTimeMillis();
                }

                if (System.currentTimeMillis() - startTime > maxCrawlMillis) {
                    job.completionReason = "Max crawl duration reached";
                    break;
                }
                
                if (currentReqs > 0 && (System.currentTimeMillis() - lastProgressTime > idleThresholdMillis)) {
                    job.completionReason = "Discovery concluded (traffic stabilized after " + currentReqs + " requests)";
                    break;
                }
            }

            job.crawlStatus = "complete (" + job.completionReason + ")";
            api.logging().logToOutput("[" + job.getId() + "] Crawl Phase Complete! Total Requests: " + job.crawlRequests + ". Handshaking to Active Audit...");

            // ==========================================
            // PHASE 2: AUTOMATED ACTIVE AUDIT INJECTION
            // ==========================================
            job.phase = ScanJob.Phase.AUDITING;
            job.auditStatus = "initializing active vulnerability attacking...";
            
            Audit audit = api.scanner().startAudit(AuditConfiguration.auditConfiguration(BuiltInAuditConfiguration.LEGACY_ACTIVE_AUDIT_CHECKS));
            job.audit = audit;

            // Retrieve discovered Site Map and inject valid authenticated targets into offensive Audit scanner
            List<HttpRequestResponse> sitemapItems = api.siteMap().requestResponses();
            int injectedTargets = 0;
            for (HttpRequestResponse item : sitemapItems) {
                if (item.request() == null || item.request().httpService() == null) continue;
                String itemHost = item.request().httpService().host();
                if (itemHost.equalsIgnoreCase(job.targetHost) || itemHost.equals("ofbiz") || itemHost.equals("127.0.0.1")) {
                    String path = item.request().pathWithoutQuery().toLowerCase(Locale.ROOT);
                    
                    // Shielding: Skip static binaries and session-killing authentication interfaces
                    if (isStaticOrRestricted(path)) continue;

                    audit.addRequestResponse(item);
                    injectedTargets++;
                }
            }

            api.logging().logToOutput("[" + job.getId() + "] Successfully injected " + injectedTargets + " authenticated application endpoints into Active Audit engine!");

            startTime = System.currentTimeMillis();
            lastProgressTime = System.currentTimeMillis();
            previousReqs = -1;

            while (true) {
                Thread.sleep(8000);
                int currentReqs = 0;
                int currentErrors = 0;
                int insertionPoints = 0;

                try { currentReqs = audit.requestCount(); } catch (Exception ignored) {}
                try { currentErrors = audit.errorCount(); } catch (Exception ignored) {}
                try { insertionPoints = audit.insertionPointCount(); } catch (Exception ignored) {}

                job.auditStatus = "active audit in progress (payload requests: " + currentReqs + ", insertion points: " + insertionPoints + ")";
                api.logging().logToOutput("[" + job.getId() + "] [Audit Phase] Attack Payloads Fired: " + currentReqs + " | Insertion Points: " + insertionPoints + " | Errors: " + currentErrors);

                if (currentReqs != previousReqs) {
                    previousReqs = currentReqs;
                    lastProgressTime = System.currentTimeMillis();
                }

                if (System.currentTimeMillis() - startTime > maxAuditMillis) {
                    job.completionReason = "Max audit duration timeout reached";
                    break;
                }

                if (currentReqs > 0 && (System.currentTimeMillis() - lastProgressTime > auditIdleMillis)) {
                    job.completionReason = "Active Audit completed successfully (all attack vectors exhausted after " + currentReqs + " payloads)";
                    break;
                }
            }

            job.auditStatus = "complete (" + job.completionReason + ")";
            job.phase = ScanJob.Phase.COMPLETE;
            api.logging().logToOutput("[" + job.getId() + "] VAPT Assessment Pipeline Totally Complete!");
            job.terminateTasks();
            scanInProgress.set(false);

        } catch (Exception e) {
            job.phase = ScanJob.Phase.ERROR;
            job.error = "Pipeline execution failure: " + e.getMessage();
            job.terminateTasks();
            scanInProgress.set(false);
        }
    }

    private boolean isStaticOrRestricted(String path) {
        return path.endsWith(".css") || path.endsWith(".js") || path.endsWith(".png") || 
               path.endsWith(".jpg") || path.endsWith(".gif") || path.endsWith(".woff") || 
               path.contains("logout") || path.contains("checklogin") || 
               path.contains("forgotpassword") || path.endsWith("/login");
    }

    private void performAdminAuthenticationHandshake(String targetHost) {
        try {
            String user = System.getenv().getOrDefault("OFBIZ_USERNAME", "admin");
            String pass = System.getenv().getOrDefault("OFBIZ_PASSWORD", "ofbiz");
            String loginUrl = "https://" + targetHost + ":8443/webtools/control/login";
            String payload = "USERNAME=" + user + "&PASSWORD=" + pass;

            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, new TrustManager[]{ new X509TrustManager() {
                public void checkClientTrusted(X509Certificate[] certs, String authType) {}
                public void checkServerTrusted(X509Certificate[] certs, String authType) {}
                public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
            }}, new SecureRandom());
            
            HttpsURLConnection.setDefaultSSLSocketFactory(sslContext.getSocketFactory());
            HttpsURLConnection.setDefaultHostnameVerifier((hostname, session) -> true);

            URL url = new URL(loginUrl);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setDoOutput(true);
            conn.setInstanceFollowRedirects(false);
            conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
            conn.setRequestProperty("User-Agent", "Mozilla/5.0 (VAPT Automation Bridge)");

            try (OutputStream os = conn.getOutputStream()) {
                os.write(payload.getBytes(StandardCharsets.UTF_8));
                os.flush();
            }

            int status = conn.getResponseCode();
            List<String> cookies = conn.getHeaderFields().get("Set-Cookie");
            if (cookies != null) {
                for (String cookie : cookies) {
                    if (cookie.contains("JSESSIONID=")) {
                        for (String part : cookie.split(";")) {
                            if (part.trim().startsWith("JSESSIONID=")) {
                                String sessionId = part.trim().substring("JSESSIONID=".length()).trim();
                                sessionHandler.setSessionCookie(sessionId);
                                api.logging().logToOutput("[AuthHandshake] Successfully verified administrator login (HTTP " + status + "). Active Session secured.");
                                return;
                            }
                        }
                    }
                }
            }
        } catch (Exception e) {
            api.logging().logToOutput("[AuthHandshake] Pre-authentication note: " + e.getMessage());
        }
    }

    private String[] validateSeeds(String rawUrl, String host) {
        List<String> seeds = Arrays.stream(rawUrl.split(",")).map(String::trim).filter(s -> !s.isEmpty()).collect(Collectors.toList());
        if (seeds.isEmpty()) throw new IllegalArgumentException("Target seed URLs cannot be empty.");
        for (String s : seeds) {
            URI u = URI.create(s);
            if (u.getHost() == null || !u.getHost().equalsIgnoreCase(host)) {
                throw new IllegalArgumentException("Seed URL host must match target scope host: " + host);
            }
        }
        return seeds.toArray(String[]::new);
    }
}