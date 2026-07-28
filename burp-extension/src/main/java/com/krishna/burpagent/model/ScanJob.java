package com.krishna.burpagent.model;

import burp.api.montoya.scanner.Crawl;
import burp.api.montoya.scanner.CrawlAndAudit;
import burp.api.montoya.scanner.audit.Audit;
import java.util.Locale;

public class ScanJob {
    public enum Phase { CRAWLING, AUDITING, COMPLETE, ERROR }

    private final String id;
    public final String targetHost;
    
    // Support for specialized Montoya scanner tasks
    public volatile Crawl crawl;
    public volatile CrawlAndAudit crawlAndAudit;
    public volatile Audit audit;
    
    public volatile Phase phase = Phase.CRAWLING;
    public volatile String error = "";
    public volatile int crawlRequests = 0;
    public volatile int auditRequests = 0;
    public volatile int issueCount = 0;
    public volatile String crawlStatus = "starting";
    public volatile String auditStatus = "waiting";
    public volatile String completionReason = "";

    public ScanJob(String id, String targetHost, Crawl crawl) {
        this.id = id;
        this.targetHost = targetHost;
        this.crawl = crawl;
    }

    public String getId() { return id; }
    public String getTargetHost() { return targetHost; }
    
    public String getPhaseString() {
        return phase.name().toLowerCase(Locale.ROOT);
    }

    public String toJsonStatus() {
        return String.format(
            "{\"id\":\"%s\",\"phase\":\"%s\",\"crawlStatus\":\"%s\",\"auditStatus\":\"%s\",\"crawlRequests\":%d,\"auditRequests\":%d,\"issueCount\":%d,\"terminal\":%b,\"error\":\"%s\"}",
            id, getPhaseString(), crawlStatus, auditStatus, crawlRequests, auditRequests, issueCount, isTerminal(), error
        );
    }

    public boolean isTerminal() {
        return phase == Phase.COMPLETE || phase == Phase.ERROR;
    }
    
    public void terminateTasks() {
        try { if (audit != null) audit.delete(); } catch (Exception ignored) {}
        try { if (crawl != null) crawl.delete(); } catch (Exception ignored) {}
        try { if (crawlAndAudit != null) crawlAndAudit.delete(); } catch (Exception ignored) {}
    }
}