package com.krishna.burpagent.launcher;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.Comparator;
import java.util.List;

final class ProjectCleanupAgent {
    private final AgentConfiguration config;
    private final CommandRunner commands;

    ProjectCleanupAgent(AgentConfiguration config, CommandRunner commands) {
        this.config = config;
        this.commands = commands;
    }

    void stopAndClean() throws Exception {
        System.out.println("=== OFBiz Burp pipeline stop and cleanup ===");
        stopManagedLauncherProcesses();
        stopManagedBurpProcesses();
        stopOrphanedBurpBrowserProcesses();
        commands.run(
                List.of("docker", "compose", "down", "--volumes", "--remove-orphans"),
                config.projectRoot(),
                Duration.ofMinutes(5)
        );
        deleteArtifacts();
        System.out.println("[Cleanup agent] Project Burp process, OFBiz runtime, and artifacts are clean.");
        System.out.println("[Cleanup agent] Native Burp installation, licence/profile, source, and Docker image cache were untouched.");
    }

    private void stopManagedLauncherProcesses() throws Exception {
        Path projectRoot = config.projectRoot().toRealPath();
        Path launcherJar = NativeBurpAgent.runningJar();
        long cleanupPid = ProcessHandle.current().pid();
        List<ProcessHandle> managed = ProcessHandle.allProcesses()
                .filter(process -> process.pid() != cleanupPid)
                .filter(process -> {
                    try {
                        Path workingDirectory = Path.of("/proc", Long.toString(process.pid()), "cwd").toRealPath();
                        return isManagedLauncherProcess(
                                process.info().arguments().orElse(new String[0]),
                                workingDirectory,
                                launcherJar,
                                projectRoot);
                    } catch (Exception ignored) {
                        return false;
                    }
                })
                .toList();
        stopProcesses(managed, "pipeline launcher", 15);
    }

    private void stopManagedBurpProcesses() throws Exception {
        List<ProcessHandle> managed = ProcessHandle.allProcesses()
                .filter(process -> isManagedBurpProcess(
                        process.info().arguments().orElse(new String[0]),
                        config.artifactsDirectory()))
                .toList();
        stopProcesses(managed, "project-managed Burp", 45);
    }

    private void stopOrphanedBurpBrowserProcesses() throws Exception {
        boolean burpMainRunning = ProcessHandle.allProcesses()
                .map(process -> process.info().commandLine().orElse(""))
                .anyMatch(NativeBurpAgent::isBurpMainCommand);
        if (burpMainRunning) {
            System.out.println("[Cleanup agent] A non-project Burp instance is running; its browser processes were preserved.");
            return;
        }
        List<ProcessHandle> orphanedBrowsers = ProcessHandle.allProcesses()
                .filter(process -> NativeBurpAgent.isBurpEmbeddedBrowserCommand(
                        process.info().commandLine().orElse("")))
                .toList();
        stopProcesses(orphanedBrowsers, "orphaned Burp embedded browser", 15);
    }

    private void stopProcesses(List<ProcessHandle> managed, String description, long timeoutSeconds)
            throws Exception {
        if (managed.isEmpty()) {
            System.out.println("[Cleanup agent] No " + description + " process is running.");
            return;
        }

        for (ProcessHandle process : managed) {
            System.out.println("[Cleanup agent] Gracefully stopping " + description + " PID " + process.pid() + "...");
            process.destroy();
        }
        Instant deadline = Instant.now().plusSeconds(timeoutSeconds);
        while (managed.stream().anyMatch(ProcessHandle::isAlive) && Instant.now().isBefore(deadline)) {
            Thread.sleep(250);
        }
        List<Long> stillRunning = managed.stream()
                .filter(ProcessHandle::isAlive)
                .map(ProcessHandle::pid)
                .toList();
        if (!stillRunning.isEmpty()) {
            throw new IllegalStateException(
                    description + " did not stop cleanly; runtime data was preserved. PIDs: " + stillRunning);
        }
    }

    private void deleteArtifacts() throws IOException {
        Path root = config.projectRoot().toAbsolutePath().normalize();
        Path artifacts = config.artifactsDirectory().toAbsolutePath().normalize();
        validateCleanupTarget(root, artifacts);
        if (!Files.exists(artifacts)) {
            System.out.println("[Cleanup agent] No generated artifacts directory exists.");
            return;
        }
        try (var paths = Files.walk(artifacts)) {
            for (Path path : paths.sorted(Comparator.reverseOrder()).toList()) {
                Files.deleteIfExists(path);
            }
        }
        System.out.println("[Cleanup agent] Removed generated artifacts: " + artifacts);
    }

    static void validateCleanupTarget(Path projectRoot, Path artifacts) {
        Path root = projectRoot.toAbsolutePath().normalize();
        Path target = artifacts.toAbsolutePath().normalize();
        if (target.equals(root) || !target.startsWith(root)) {
            throw new IllegalArgumentException(
                    "ARTIFACTS_DIR cleanup target must be a child of the project root: " + target);
        }
    }

    static boolean isManagedBurpProcess(String[] arguments, Path artifactsDirectory) {
        Path artifacts = artifactsDirectory.toAbsolutePath().normalize();
        for (String argument : arguments) {
            if (!argument.startsWith("--project-file=")) continue;
            try {
                Path projectFile = Path.of(argument.substring("--project-file=".length()))
                        .toAbsolutePath()
                        .normalize();
                Path runDirectory = projectFile.getParent();
                return runDirectory != null
                        && runDirectory.getParent() != null
                        && runDirectory.getParent().equals(artifacts)
                        && runDirectory.getFileName().toString().startsWith("run-")
                        && projectFile.getFileName().toString().equals("burp-project.burp");
            } catch (Exception ignored) {
                return false;
            }
        }
        return false;
    }

    static boolean isManagedLauncherProcess(
            String[] arguments,
            Path workingDirectory,
            Path launcherJar,
            Path projectRoot) {
        if (!workingDirectory.toAbsolutePath().normalize().equals(projectRoot.toAbsolutePath().normalize())) {
            return false;
        }
        for (int index = 0; index < arguments.length - 1; index++) {
            if (!"-jar".equals(arguments[index])) continue;
            Path argumentPath = Path.of(arguments[index + 1]);
            Path resolved = (argumentPath.isAbsolute()
                    ? argumentPath
                    : workingDirectory.resolve(argumentPath)).toAbsolutePath().normalize();
            return resolved.equals(launcherJar.toAbsolutePath().normalize());
        }
        return false;
    }
}
