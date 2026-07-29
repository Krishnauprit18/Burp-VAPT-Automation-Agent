package com.krishna.burpagent.service;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.scanner.audit.AuditIssueHandler;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;

public final class AuditIssueLoggingHandler implements AuditIssueHandler {
    private final MontoyaApi api;
    private final ConfigurationService configService;

    public AuditIssueLoggingHandler(MontoyaApi api, ConfigurationService configService) {
        this.api = api;
        this.configService = configService;
    }

    @Override
    public void handleNewAuditIssue(AuditIssue auditIssue) {
        String logMsg = String.format("[AuditAlert] [%s Severity] Found '%s' at %s",
                auditIssue.severity().name(), auditIssue.name(), auditIssue.baseUrl());

        configService.logDiagnostics(logMsg);

        if (auditIssue.severity() == AuditIssueSeverity.HIGH) {
            api.logging().logToOutput(">>> HIGH-SEVERITY VAPT FINDING: " + logMsg);
        } else {
            api.logging().logToOutput(logMsg);
        }
    }
}
