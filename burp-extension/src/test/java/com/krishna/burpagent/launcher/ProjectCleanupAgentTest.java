package com.krishna.burpagent.launcher;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

final class ProjectCleanupAgentTest {
    @TempDir
    Path projectRoot;

    @Test
    void identifiesOnlyBurpProcessesOwnedByThisProject() {
        Path artifacts = projectRoot.resolve("artifacts");
        String managedProject = "--project-file="
                + artifacts.resolve("run-20260729-120000/burp-project.burp");

        assertTrue(ProjectCleanupAgent.isManagedBurpProcess(
                new String[]{"install4j.burp.StartBurp", managedProject}, artifacts));
        assertFalse(ProjectCleanupAgent.isManagedBurpProcess(
                new String[]{"install4j.burp.StartBurp", "--project-file=/tmp/personal.burp"}, artifacts));
        assertFalse(ProjectCleanupAgent.isManagedBurpProcess(
                new String[]{"install4j.burp.StartBurp"}, artifacts));
    }

    @Test
    void refusesCleanupOutsideTheProjectRoot() {
        ProjectCleanupAgent.validateCleanupTarget(projectRoot, projectRoot.resolve("artifacts"));
        assertThrows(IllegalArgumentException.class,
                () -> ProjectCleanupAgent.validateCleanupTarget(projectRoot, projectRoot));
        assertThrows(IllegalArgumentException.class,
                () -> ProjectCleanupAgent.validateCleanupTarget(projectRoot, projectRoot.getParent()));
    }

    @Test
    void identifiesOnlyLaunchersFromThisProjectAndJar() {
        Path launcher = projectRoot.resolve("burp-extension/target/burp-agent-bridge.jar");

        assertTrue(ProjectCleanupAgent.isManagedLauncherProcess(
                new String[]{"-jar", "burp-extension/target/burp-agent-bridge.jar"},
                projectRoot,
                launcher,
                projectRoot));
        assertFalse(ProjectCleanupAgent.isManagedLauncherProcess(
                new String[]{"-jar", "burp-extension/target/burp-agent-bridge.jar"},
                projectRoot.resolve("another-project"),
                launcher,
                projectRoot));
        assertFalse(ProjectCleanupAgent.isManagedLauncherProcess(
                new String[]{"-jar", "unrelated.jar"},
                projectRoot,
                launcher,
                projectRoot));
    }
}
