package com.krishna.burpagent;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import com.krishna.burpagent.server.MontoyaBridgeServer;
import com.krishna.burpagent.service.AuditIssueLoggingHandler;
import com.krishna.burpagent.service.ConfigurationService;
import com.krishna.burpagent.service.CrawlerSessionCoordinator;
import com.krishna.burpagent.service.OFBizAuthenticationService;
import com.krishna.burpagent.service.ReportAgent;
import com.krishna.burpagent.service.SessionAuthenticationHandler;

public final class BurpAgentExtension implements BurpExtension {
    private MontoyaBridgeServer server;
    private OFBizAuthenticationService authenticationService;

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

            this.authenticationService = new OFBizAuthenticationService(api, configService);
            CrawlerSessionCoordinator sessionCoordinator = new CrawlerSessionCoordinator();
            SessionAuthenticationHandler sessionHandler = new SessionAuthenticationHandler(
                    configService, authenticationService, sessionCoordinator);
            AuditIssueLoggingHandler auditIssueHandler = new AuditIssueLoggingHandler(api, configService);
            ReportAgent reportAgent = new ReportAgent(api, configService);
            this.server = new MontoyaBridgeServer(
                    configService,
                    authenticationService,
                    sessionCoordinator,
                    reportAgent,
                    port,
                    token);

            api.http().registerHttpHandler(sessionHandler);
            api.scanner().registerAuditIssueHandler(auditIssueHandler);
            authenticationService.startMonitoring();
            this.server.start();

            String successMsg = "Native Burp Java agents ready on loopback port " + port;
            configService.logDiagnostics(successMsg);
            api.logging().logToOutput(successMsg);

            api.extension().registerUnloadingHandler(() -> {
                configService.logDiagnostics("Extension unloading, shutting down socket listeners.");
                if (server != null) server.stop();
                if (authenticationService != null) authenticationService.stop();
            });
        } catch (Throwable e) {
            configService.logDiagnostics("Fatal Startup Exception: " + e.getMessage());
            api.logging().logToError("Extension initialization failed: " + e.getMessage());
            throw new IllegalStateException(e);
        }
    }
}
