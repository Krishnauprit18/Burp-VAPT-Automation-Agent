package com.krishna.burpagent.model;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

final class TargetScopeTest {
    @Test
    void acceptsOnlyTheExactWebToolsSeed() {
        TargetScope target = TargetScope.webTools(TargetScope.DEFAULT_URL);

        assertEquals("localhost", target.host());
        assertEquals(8443, target.port());
        assertEquals(TargetScope.DEFAULT_URL, target.url());
        assertTrue(target.allowsPath("/webtools/control/main"));
    }

    @Test
    void rejectsAnyConfiguredSeedOtherThanTheApprovedWebToolsUrl() {
        assertThrows(IllegalArgumentException.class,
                () -> TargetScope.webTools("https://localhost:8443/ecommerce/control/main"));
        assertThrows(IllegalArgumentException.class,
                () -> TargetScope.webTools("https://localhost:8443/accounting/control/main"));
        assertThrows(IllegalArgumentException.class,
                () -> TargetScope.webTools("https://127.0.0.1:8443/webtools/control/main"));
    }

    @Test
    void allowsEveryTargetPathExceptEcommerce() {
        TargetScope target = TargetScope.webTools(TargetScope.DEFAULT_URL);

        assertTrue(target.allowsPath("/webtools/control/main"));
        assertTrue(target.allowsPath("/accounting/control/main"));
        assertTrue(target.allowsPath("/party/control/main"));
        assertTrue(target.allowsPath("/common/js/util/ofbizutil.js"));
        assertTrue(target.allowsPath("/helveticus/style.css"));
        assertTrue(target.allowsPath("/"));
        assertFalse(target.allowsPath("/ecommerce"));
        assertFalse(target.allowsPath("/ecommerce/control/main"));
        assertFalse(target.allowsPath("/ECOMMERCE/control/main"));
    }

    @Test
    void identifiesOnlyApplicationLogoutEndpoints() {
        TargetScope target = TargetScope.webTools(TargetScope.DEFAULT_URL);

        assertTrue(target.isLogoutPath("/webtools/control/logout"));
        assertTrue(target.isLogoutPath("/ACCOUNTING/control/logout"));
        assertFalse(target.isLogoutPath("/webtools/control/login"));
        assertFalse(target.isLogoutPath("/common/js/logout-helper.js"));
        assertTrue(target.isLoginPath("/webtools/control/login"));
        assertTrue(target.isLoginPath("/ACCOUNTING/control/login"));
        assertFalse(target.isLoginPath("/webtools/control/checkLogin"));
    }

    @Test
    void limitsStandbySessionInjectionToTheWebtoolsServletContext() {
        TargetScope target = TargetScope.webTools(TargetScope.DEFAULT_URL);

        assertTrue(target.usesPrimaryApplicationSession("/webtools"));
        assertTrue(target.usesPrimaryApplicationSession("/webtools/control/main"));
        assertFalse(target.usesPrimaryApplicationSession("/partymgr/control/main"));
        assertFalse(target.usesPrimaryApplicationSession("/accounting/control/main"));
        assertFalse(target.usesPrimaryApplicationSession("/common-js/control/main"));
    }
}
