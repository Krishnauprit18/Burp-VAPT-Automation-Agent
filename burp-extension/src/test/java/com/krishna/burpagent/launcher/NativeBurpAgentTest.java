package com.krishna.burpagent.launcher;

import org.junit.jupiter.api.Test;

import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

final class NativeBurpAgentTest {
    @Test
    void launchesDesktopBurpProfileWithoutAUserConfigOverride() {
        List<String> command = NativeBurpAgent.launchCommand(
                Path.of("/home/krishna/BurpSuite/BurpSuite"),
                Path.of("/tmp/run/burp-project.burp"));

        assertEquals(List.of(
                "/home/krishna/BurpSuite/BurpSuite",
                "--project-file=/tmp/run/burp-project.burp"
        ), command);
        assertFalse(command.stream().anyMatch(argument -> argument.startsWith("--user-config-file=")));
    }

    @Test
    void distinguishesBurpMainFromItsEmbeddedBrowser() {
        assertTrue(NativeBurpAgent.isBurpMainCommand(
                "/home/krishna/BurpSuite/jre/bin/java -classpath /home/krishna/BurpSuite/burpsuite.jar "
                        + "install4j.burp.StartBurp --project-file=/tmp/test.burp"));
        assertFalse(NativeBurpAgent.isBurpMainCommand(
                "/home/krishna/BurpSuite/burpbrowser/150/chrome --headless=old"));
        assertTrue(NativeBurpAgent.isBurpEmbeddedBrowserCommand(
                "/home/krishna/BurpSuite/burpbrowser/150/chrome --headless=old"));
    }
}
