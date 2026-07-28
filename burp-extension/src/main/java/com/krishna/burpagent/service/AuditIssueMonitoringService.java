package com.krishna.burpagent.service;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.scanner.audit.AuditIssueHandler;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

public class AuditIssueMonitoringService implements AuditIssueHandler {
    private final MontoyaApi api;
    private final ConfigurationService configService;
    private final List<AuditIssue> discoveredIssues = new CopyOnWriteArrayList<>();

    public AuditIssueMonitoringService(MontoyaApi api, ConfigurationService configService) {
        this.api = api;
        this.configService = configService;
    }

    @Override
    public void handleNewAuditIssue(AuditIssue auditIssue) {
        discoveredIssues.add(auditIssue);
        
        String logMsg = String.format("[AuditAlert] [%s Severity] Found '%s' at %s", 
                auditIssue.severity().name(), auditIssue.name(), auditIssue.baseUrl());
        
        configService.logDiagnostics(logMsg);
        
        // Emphasize critical and high severity findings in terminal output
        if (auditIssue.severity() == AuditIssueSeverity.HIGH || auditIssue.severity() == AuditIssueSeverity.MEDIUM) {
            api.logging().logToOutput(">>> 🚨 CRITICAL VAP-T FINDING: " + logMsg);
        } else {
            api.logging().logToOutput(logMsg);
        }
    }

    public List<AuditIssue> getDiscoveredIssues() {
        return discoveredIssues;
    }

    public long getIssueCountBySeverity(AuditIssueSeverity severity) {
        return discoveredIssues.stream().filter(i -> i.severity() == severity).count();
    }
}