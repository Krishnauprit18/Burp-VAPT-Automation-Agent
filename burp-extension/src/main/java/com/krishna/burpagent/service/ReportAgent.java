package com.krishna.burpagent.service;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.scanner.ReportFormat;
import burp.api.montoya.scanner.audit.issues.AuditIssue;

import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

public final class ReportAgent {
    private final MontoyaApi api;
    private final ConfigurationService config;

    public ReportAgent(MontoyaApi api, ConfigurationService config) {
        this.api = api;
        this.config = config;
    }

    public ReportResult generate(String taskId) throws Exception {
        List<AuditIssue> issues = api.siteMap().issues().stream()
                .filter(this::belongsToAssessment)
                .toList();
        Files.createDirectories(config.artifactsDirectory());
        Path html = config.artifactsDirectory().resolve("burp-report-" + taskId + ".html");
        Path xml = config.artifactsDirectory().resolve("burp-report-" + taskId + ".xml");
        api.scanner().generateReport(issues, ReportFormat.HTML, html);
        api.scanner().generateReport(issues, ReportFormat.XML, xml);
        api.logging().logToOutput("[Report agent] Generated Burp-native HTML and XML reports for "
                + issues.size() + " audit issues.");
        return new ReportResult(issues.size(), html, xml);
    }

    private boolean belongsToAssessment(AuditIssue issue) {
        try {
            if (issue.httpService() == null
                    || !issue.httpService().host().equalsIgnoreCase(config.targetHost())
                    || issue.httpService().port() != config.targetPort()) {
                return false;
            }
            String path = URI.create(issue.baseUrl()).getPath();
            return config.isAllowedPath(path);
        } catch (Exception ignored) {
            return false;
        }
    }

    public record ReportResult(int issueCount, Path html, Path xml) {}
}
