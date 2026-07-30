package com.krishna.burpagent.service;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

final class CrawlerSessionCoordinatorTest {
    @Test
    void startsInRecoveryModeForRestoredBurpTasks() {
        CrawlerSessionCoordinator coordinator = new CrawlerSessionCoordinator();

        assertEquals(
                CrawlerSessionCoordinator.Mode.AGENT_RECOVERY_SESSION,
                coordinator.mode());
        assertTrue(coordinator.shouldInjectAgentSession());
    }

    @Test
    void freshScanPreparationWaitsForBurpCredentialLogin() {
        CrawlerSessionCoordinator coordinator = new CrawlerSessionCoordinator();

        coordinator.beginCredentialLogin();

        assertEquals(
                CrawlerSessionCoordinator.Mode.AWAITING_BURP_CREDENTIAL_LOGIN,
                coordinator.mode());
        assertFalse(coordinator.shouldInjectAgentSession());
    }

    @Test
    void keepsAgentSessionOnStandbyAfterBurpLogin() {
        CrawlerSessionCoordinator coordinator = new CrawlerSessionCoordinator();

        assertTrue(coordinator.establishBurpCredentialSession("crawler-session"));
        assertTrue(coordinator.burpCredentialLoginEstablished());
        assertFalse(coordinator.shouldInjectAgentSession());
        assertEquals("crawler-session", coordinator.burpSessionId());
        assertFalse(coordinator.establishBurpCredentialSession("crawler-session"));
    }

    @Test
    void injectsAgentSessionOnlyAfterRecoveryActivation() {
        CrawlerSessionCoordinator coordinator = new CrawlerSessionCoordinator();
        coordinator.establishBurpCredentialSession("crawler-session");

        assertTrue(coordinator.activateAgentRecoverySession());
        assertTrue(coordinator.shouldInjectAgentSession());
        assertFalse(coordinator.burpCredentialLoginEstablished());
        assertFalse(coordinator.activateAgentRecoverySession());
    }

    @Test
    void successfulBurpReloginEndsAgentRecovery() {
        CrawlerSessionCoordinator coordinator = new CrawlerSessionCoordinator();
        coordinator.activateAgentRecoverySession();

        assertTrue(coordinator.establishBurpCredentialSession("new-crawler-session"));
        assertTrue(coordinator.burpCredentialLoginEstablished());
        assertFalse(coordinator.shouldInjectAgentSession());
        assertEquals("new-crawler-session", coordinator.burpSessionId());
    }
}
