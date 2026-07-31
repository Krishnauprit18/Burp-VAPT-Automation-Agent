package com.krishna.burpagent.launcher;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

final class BurpRestClientTest {
    private static final ObjectMapper JSON = new ObjectMapper();

    @TempDir
    Path tempDirectory;

    @Test
    void buildsNativeAuthenticatedCrawlAndAuditWithCustomConfigurations() throws Exception {
        AgentConfiguration config = configuration();

        JsonNode request = BurpRestClient.buildScanRequest(config);

        assertEquals(
                "https://localhost:8443/webtools/control/main",
                request.path("urls").get(0).asText());
        assertFalse(request.has("name"));
        assertEquals("specified", request.path("protocol_option").asText());
        
        // Scope is no longer built manually
        assertTrue(request.path("scope").isMissingNode());
        
        // Application login defaults to .env if json doesn't exist
        assertEquals(
                "UsernameAndPasswordLogin",
                request.path("application_logins").get(0).path("type").asText());
        assertEquals("admin", request.path("application_logins").get(0).path("username").asText());
        assertEquals("ofbiz", request.path("application_logins").get(0).path("password").asText());
        
        // Custom configs should be empty since we didn't create them in the test's temp config dir
        assertTrue(request.has("scan_configurations"));
        assertEquals(0, request.path("scan_configurations").size());
    }

    @Test
    void parsesBurpOwnedLifecycleAndMetrics() throws Exception {
        JsonNode response = JSON.readTree("""
                {
                  "task_id": "42",
                  "scan_status": "auditing",
                  "message": "Auditing",
                  "scan_metrics": {
                    "crawl_and_audit_progress": 63,
                    "crawl_requests_made": 120,
                    "crawl_unique_locations_visited": 35,
                    "audit_requests_made": 900,
                    "issue_events": 7
                  },
                  "issue_events": []
                }
                """);

        BurpRestClient.ScanProgress progress = BurpRestClient.ScanProgress.from(response);

        assertEquals("42", progress.taskId());
        assertEquals("auditing", progress.status());
        assertEquals(63, progress.percent());
        assertEquals(120, progress.crawlRequests());
        assertEquals(35, progress.uniqueLocations());
        assertEquals(900, progress.auditRequests());
        assertEquals(7, progress.issueEvents());
    }

    private AgentConfiguration configuration() throws Exception {
        Files.writeString(tempDirectory.resolve(".env"), """
                OFBIZ_SOURCE=%s
                TARGET_URL=https://localhost:8443/webtools/control/main
                OFBIZ_USERNAME=admin
                OFBIZ_PASSWORD=ofbiz
                BURP_BRIDGE_TOKEN=0123456789abcdef0123456789abcdef
                BURP_REST_API_URL=http://127.0.0.1:1337
                BURP_REST_API_KEY=0123456789abcdef0123456789abcdef
                """.formatted(tempDirectory));
        return AgentConfiguration.load(tempDirectory);
    }
}
