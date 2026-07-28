package com.krishna.burpagent;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import com.krishna.burpagent.server.RestSocketServer;
import com.krishna.burpagent.service.AuditIssueMonitoringService;
import com.krishna.burpagent.service.ConfigurationService;
import com.krishna.burpagent.service.ScanEngineService;
import com.krishna.burpagent.service.SessionAuthenticationHandler;

public final class BurpAgentExtension implements BurpExtension {
    private RestSocketServer server;

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("OFBiz Burp Agent Bridge (Automated VAPT Pipeline)");
        ConfigurationService configService = new ConfigurationService(api);
        
        try {
            String token = configService.getSecurityToken();
            if (token.length() < 32) {
                throw new IllegalStateException("BURP_BRIDGE_TOKEN missing or less than 32 characters.");
            }
            int port = Integer.parseInt(System.getenv().getOrDefault("BURP_BRIDGE_PORT", "1338"));

            // 1. Initialize Autonomous Services & Security Handlers
            SessionAuthenticationHandler sessionHandler = new SessionAuthenticationHandler(api, configService);
            AuditIssueMonitoringService auditIssueHandler = new AuditIssueMonitoringService(api, configService);
            ScanEngineService scanEngine = new ScanEngineService(api, configService, sessionHandler);
            this.server = new RestSocketServer(api, configService, scanEngine, port, token);

            // 2. Register Native Montoya Interception & Alerting Shields
            api.http().registerHttpHandler(sessionHandler);
            api.scanner().registerAuditIssueHandler(auditIssueHandler);
            configService.injectAggressiveScanRules();
            
            // 3. Start REST Presentation Controller
            this.server.start();

            String successMsg = "Modular Burp Bridge running on port " + port + " (Crawl + Active Audit Pipeline Armed)";
            configService.logDiagnostics(successMsg);
            api.logging().logToOutput(successMsg);

            api.extension().registerUnloadingHandler(() -> {
                configService.logDiagnostics("Extension unloading, shutting down socket listeners.");
                if (server != null) server.stop();
            });
        } catch (Throwable e) {
            configService.logDiagnostics("Fatal Startup Exception: " + e.getMessage());
            api.logging().logToError("Extension initialization failed: " + e.getMessage());
            throw new IllegalStateException(e);
        }
    }
}