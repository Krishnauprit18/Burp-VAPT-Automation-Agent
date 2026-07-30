package com.krishna.burpagent.service;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

final class ConfigurationServiceTest {
    @Test
    void configuresApprovedScopeAndCrawlerSafetyExclusions() {
        String json = ConfigurationService.buildProjectOptionsJson(
                "localhost", 8443);

        assertTrue(json.contains("(?i)^/ecommerce(?:/.*)?$"));
        assertTrue(json.contains("(?i)^/[^/]+/control/logout(?:/.*)?$"));
        assertFalse(json.contains("ListLocales|setSessionLocale|setUserLocale"));
        assertFalse(json.contains("ListVisualThemes|selectTheme|setUserPreference"));
        assertFalse(json.contains("common-js/control/SetTimeZoneFromBrowser"));
        assertTrue(json.contains("\"file\": \"^/.*\""));
        assertFalse(json.contains("non-WebTools"));
        assertFalse(json.contains("forgotPassword"));
        assertFalse(json.contains("checkLogin"));
        assertFalse(json.contains("application_logins"));
        assertFalse(json.contains("read_timeout_millis"));
        assertFalse(json.contains("max_concurrent_requests"));
    }
}
