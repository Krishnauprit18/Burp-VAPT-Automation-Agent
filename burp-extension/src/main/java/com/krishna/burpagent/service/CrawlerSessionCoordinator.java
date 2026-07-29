package com.krishna.burpagent.service;

import java.util.concurrent.atomic.AtomicReference;

public final class CrawlerSessionCoordinator {
    enum Mode {
        AWAITING_BURP_CREDENTIAL_LOGIN,
        BURP_CREDENTIAL_SESSION,
        AGENT_RECOVERY_SESSION
    }

    private final AtomicReference<Mode> mode =
            new AtomicReference<>(Mode.AWAITING_BURP_CREDENTIAL_LOGIN);
    private final AtomicReference<String> burpSessionId = new AtomicReference<>("");

    public void beginCredentialLogin() {
        burpSessionId.set("");
        mode.set(Mode.AWAITING_BURP_CREDENTIAL_LOGIN);
    }

    public boolean establishBurpCredentialSession(String sessionId) {
        if (sessionId == null || sessionId.isBlank()) {
            throw new IllegalArgumentException("Burp crawler JSESSIONID must not be blank");
        }
        burpSessionId.set(sessionId);
        return mode.getAndSet(Mode.BURP_CREDENTIAL_SESSION)
                != Mode.BURP_CREDENTIAL_SESSION;
    }

    public boolean activateAgentRecoverySession() {
        return mode.getAndSet(Mode.AGENT_RECOVERY_SESSION)
                != Mode.AGENT_RECOVERY_SESSION;
    }

    public boolean burpCredentialLoginEstablished() {
        return mode.get() == Mode.BURP_CREDENTIAL_SESSION;
    }

    public boolean shouldInjectAgentSession() {
        return mode.get() == Mode.AGENT_RECOVERY_SESSION;
    }

    public String burpSessionId() {
        return mode.get() == Mode.BURP_CREDENTIAL_SESSION ? burpSessionId.get() : "";
    }

    Mode mode() {
        return mode.get();
    }
}
