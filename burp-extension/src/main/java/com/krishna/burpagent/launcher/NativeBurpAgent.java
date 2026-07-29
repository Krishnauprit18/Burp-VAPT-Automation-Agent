package com.krishna.burpagent.launcher;

import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Locale;

final class NativeBurpAgent {
    private final AgentConfiguration config;

    NativeBurpAgent(AgentConfiguration config) {
        this.config = config;
    }

    void validateInstallation() throws Exception {
        Path executable = config.burpExecutable();
        if (!Files.isExecutable(executable)) {
            throw new IllegalArgumentException("Native Burp executable is missing or not executable: " + executable);
        }
        runningJar();
    }

    void ensureCanStart() throws Exception {
        validateInstallation();
        if (isBurpAlreadyRunning()) {
            throw new IllegalStateException(
                    "Native Burp is already running without this pipeline bridge. "
                            + "It was not stopped or modified. Close it normally, then start the agent again."
            );
        }
    }

    Process start(Path runDirectory) throws Exception {
        ensureCanStart();
        Path executable = config.burpExecutable();
        Path projectFile = runDirectory.resolve("burp-project.burp");

        ProcessBuilder builder = new ProcessBuilder(launchCommand(executable, projectFile));
        builder.environment().putAll(config.extensionEnvironment(runDirectory));
        builder.redirectErrorStream(true);
        builder.redirectOutput(runDirectory.resolve("burp-native.log").toFile());
        System.out.println("[Burp agent] Starting the desktop Burp installation with its normal user profile.");
        System.out.println("[Burp agent] Run project: " + projectFile);
        System.out.println("[Burp agent] Installation and licence data will not be modified or deleted.");
        return builder.start();
    }

    static List<String> launchCommand(Path executable, Path projectFile) {
        return List.of(
                executable.toString(),
                "--project-file=" + projectFile
        );
    }

    static Path runningJar() throws URISyntaxException {
        Path location = Path.of(MasterPipelineAgent.class.getProtectionDomain()
                .getCodeSource().getLocation().toURI()).toAbsolutePath().normalize();
        if (!Files.isRegularFile(location) || !location.toString().endsWith(".jar")) {
            throw new IllegalStateException("Run the packaged agent JAR, not loose Maven classes: " + location);
        }
        return location;
    }

    private boolean isBurpAlreadyRunning() {
        return ProcessHandle.allProcesses()
                .map(handle -> handle.info().commandLine().orElse("").toLowerCase(Locale.ROOT))
                .anyMatch(NativeBurpAgent::isBurpMainCommand);
    }

    static boolean isBurpMainCommand(String command) {
        String normalized = command == null ? "" : command.toLowerCase(Locale.ROOT);
        return normalized.contains("install4j.burp.startburp")
                || (normalized.contains("java") && normalized.contains("burpsuite.jar"));
    }

    static boolean isBurpEmbeddedBrowserCommand(String command) {
        String normalized = command == null ? "" : command.toLowerCase(Locale.ROOT);
        return normalized.contains("/burpsuite/burpbrowser/")
                && normalized.contains("/chrome");
    }

}
