package com.krishna.burpagent.launcher;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

public final class MasterPipelineAgent {
    private MasterPipelineAgent() {}

    public static void main(String[] args) {
        try {
            Path root = locateProjectRoot();
            AgentConfiguration config = AgentConfiguration.load(root);
            String mode = parseMode(args);
            if ("stop-clean".equals(mode)) {
                new ProjectCleanupAgent(config, new CommandRunner()).stopAndClean();
                return;
            }

            NativeBurpAgent nativeBurpAgent = new NativeBurpAgent(config);
            BurpRestClient burpRestClient = new BurpRestClient(config);
            if ("check".equals(mode)) {
                nativeBurpAgent.validateInstallation();
                System.out.println("[Check] Native Burp executable, REST API configuration, agent JAR, "
                        + "and target " + config.targetUrl() + " are valid.");
                return;
            }

            MontoyaBridgeClient bridge = new MontoyaBridgeClient(config);
            if (bridge.isHealthy()) {
                throw new IllegalStateException(
                        "A Burp bridge is already running. It was left untouched. "
                                + "Close the existing Burp instance normally before starting a fresh pipeline."
                );
            }
            nativeBurpAgent.ensureCanStart();

            Path runDirectory = config.artifactsDirectory().resolve(
                    "run-" + LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss")));
            Files.createDirectories(runDirectory);

            System.out.println("=== OFBiz Burp multi-agent pipeline ===");
            new OfbizDeploymentAgent(config, new CommandRunner()).deployAndWait();

            Process burp = nativeBurpAgent.start(runDirectory);
            bridge.awaitHealthy(burp);
            burpRestClient.awaitReady(burp);
            bridge.prepareScan();

            BurpRestClient.ScanTask scanTask = burpRestClient.startScan();
            BurpRestClient.ScanProgress progress =
                    burpRestClient.awaitCompletion(scanTask, runDirectory);
            String reportSummary = bridge.generateReports(scanTask.id(), runDirectory);

            System.out.println("[Report agent] Burp-native HTML and XML reports generated.");
            System.out.println("[Report agent] " + reportSummary);
            System.out.println("[Master agent] Burp task " + progress.taskId()
                    + " completed with status " + progress.status() + ".");
            System.out.println("[Master agent] Pipeline complete. Native Burp and OFBiz remain running.");
            System.out.println("[Master agent] Run artifacts: " + runDirectory);
        } catch (Exception e) {
            System.err.println("[Master agent] Pipeline failed: " + e.getMessage());
            System.exit(1);
        }
    }

    private static String parseMode(String[] args) {
        if (args.length == 0) return "start";
        if (args.length == 1 && "--check".equals(args[0])) return "check";
        if (args.length == 1 && "--stop-clean".equals(args[0])) return "stop-clean";
        throw new IllegalArgumentException(
                "Usage: java -jar burp-agent-bridge.jar [--check|--stop-clean]");
    }

    private static Path locateProjectRoot() throws Exception {
        Path current = Path.of("").toAbsolutePath().normalize();
        if (Files.isRegularFile(current.resolve("docker-compose.yml"))) return current;
        Path jar = NativeBurpAgent.runningJar();
        Path candidate = jar.getParent();
        if (candidate != null) candidate = candidate.getParent();
        if (candidate != null) candidate = candidate.getParent();
        if (candidate != null && Files.isRegularFile(candidate.resolve("docker-compose.yml"))) return candidate;
        throw new IllegalStateException("Run the agent from the project root");
    }
}
