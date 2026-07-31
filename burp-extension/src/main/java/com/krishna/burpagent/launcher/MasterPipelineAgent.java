package com.krishna.burpagent.launcher;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Comparator;
import java.util.Optional;
import java.util.Scanner;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Stream;

public final class MasterPipelineAgent {
    private MasterPipelineAgent() {}

    public static void main(String[] args) {
        try {
            Path root = locateProjectRoot();
            AgentConfiguration config = AgentConfiguration.load(root);
            String mode = parseMode(args);

            // ── Stop-clean ─────────────────────────────────────────────────
            if ("stop-clean".equals(mode)) {
                new ProjectCleanupAgent(config, new CommandRunner()).stopAndClean();
                return;
            }

            NativeBurpAgent nativeBurpAgent = new NativeBurpAgent(config);
            BurpRestClient burpRestClient = new BurpRestClient(config);

            // ── Config check ───────────────────────────────────────────────
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
                                + "Close the existing Burp instance normally before starting a fresh pipeline.");
            }
            nativeBurpAgent.ensureCanStart();

            // ── Resolve run directory and mode ─────────────────────────────
            boolean isResume;
            Path runDirectory;

            if ("new".equals(mode)) {
                // --new: force fresh scan, skip prompt
                isResume = false;
                runDirectory = newRunDirectory(config);
            } else {
                Optional<RunStateFile.RunState> savedState =
                        RunStateFile.loadLatest(config.artifactsDirectory());

                if (savedState.isPresent() && savedState.get().isResumable()) {
                    RunStateFile.RunState state = savedState.get();
                    if ("resume".equals(mode)) {
                        // --resume: skip prompt, always resume
                        isResume = true;
                        runDirectory = state.runDirectory();
                        System.out.println("[Master agent] Resuming previous session: "
                                + state.summaryLine());
                    } else {
                        // Interactive prompt
                        String choice = promptUser(state);
                        if ("q".equals(choice)) {
                            System.out.println("[Master agent] Exiting on user request.");
                            return;
                        }
                        isResume = "r".equals(choice);
                        runDirectory = isResume ? state.runDirectory() : newRunDirectory(config);
                        if (isResume) {
                            System.out.println("[Master agent] Resuming: " + state.summaryLine());
                        }
                    }
                } else {
                    // No previous session — straight to fresh scan
                    isResume = false;
                    runDirectory = newRunDirectory(config);
                }
            }

            // ── Shutdown hook — saves state on Ctrl+C ──────────────────────
            final Path finalRunDir = runDirectory;
            AtomicReference<BurpRestClient.ScanTask> activeTaskRef = new AtomicReference<>();
            AtomicReference<BurpRestClient.ScanProgress> lastProgressRef = new AtomicReference<>();

            Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                BurpRestClient.ScanTask task = activeTaskRef.get();
                BurpRestClient.ScanProgress prog = lastProgressRef.get();
                if (task != null) {
                    String status = prog != null ? prog.status() : "unknown";
                    int pct = prog != null ? prog.percent() : 0;
                    RunStateFile.save(finalRunDir, task.id(), status, pct);
                    System.out.println();
                    System.out.println("[Master agent] Scan state saved (Task #" + task.id()
                            + ", " + status + ", " + pct + "%).");
                    System.out.println("[Master agent] Next time just run:");
                    System.out.println("  java -jar burp-agent-bridge.jar");
                    System.out.println("[Master agent] To pause Burp scan: Dashboard → Task #"
                            + task.id() + " → right-click → Pause");
                }
            }, "state-saver"));

            // ── Pipeline ───────────────────────────────────────────────────
            System.out.println("=== OFBiz Burp multi-agent pipeline ===");
            new OfbizDeploymentAgent(config, new CommandRunner()).deployAndWait();

            Process burp = nativeBurpAgent.start(runDirectory);
            bridge.awaitHealthy(burp);
            burpRestClient.awaitReady(burp);

            BurpRestClient.ScanTask scanTask;

            if (isResume) {
                Optional<RunStateFile.RunState> stateOpt =
                        RunStateFile.loadLatest(config.artifactsDirectory());
                String savedTaskId = stateOpt.map(RunStateFile.RunState::taskId).orElse("");
                Optional<BurpRestClient.ScanTask> attached =
                        savedTaskId.isBlank() ? Optional.empty()
                                : burpRestClient.tryAttachExistingTask(savedTaskId);

                if (attached.isPresent()) {
                    scanTask = attached.get();
                    bridge.prepareResumedScan();
                    System.out.println("[Master agent] Monitoring resumed. "
                            + "If Burp Dashboard shows 'paused', click Play on Task #"
                            + scanTask.id() + ".");
                } else {
                    // Task ID stale — start new scan in same run directory
                    System.out.println("[Master agent] Previous task ID no longer valid "
                            + "(Burp may have been fully restarted). "
                            + "Starting a new scan in the existing run directory.");
                    bridge.prepareScan();
                    scanTask = burpRestClient.startScan();
                }
            } else {
                bridge.prepareScan();
                scanTask = burpRestClient.startScan();
            }

            activeTaskRef.set(scanTask);

            BurpRestClient.ScanProgress progress =
                    burpRestClient.awaitCompletion(scanTask, runDirectory, lastProgressRef);

            // Scan finished — remove state file so next launch starts fresh
            try {
                Files.deleteIfExists(runDirectory.resolve(RunStateFile.STATE_FILENAME));
            } catch (IOException ignored) {}

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

    // ── Helpers ────────────────────────────────────────────────────────────

    private static String promptUser(RunStateFile.RunState state) {
        System.out.println();
        System.out.println("+---------------------------------------------------------+");
        System.out.println("|  Previous scan session detected                         |");
        System.out.println("+---------------------------------------------------------+");
        System.out.println("|  " + padRight(state.summaryLine(), 57) + "|");
        System.out.println("+---------------------------------------------------------+");
        System.out.println("|  [R] Resume monitoring  [N] New scan  [Q] Quit          |");
        System.out.println("+---------------------------------------------------------+");
        System.out.print("Your choice: ");

        String choice = "";
        try {
            Scanner sc = new Scanner(System.in);
            if (sc.hasNextLine()) choice = sc.nextLine().trim().toLowerCase();
        } catch (Exception ignored) {}

        if ("n".equals(choice) || "new".equals(choice)) {
            return "n";
        } else if ("q".equals(choice) || "quit".equals(choice)) {
            return "q";
        } else {
            return "r";
        }
    }

    private static String padRight(String s, int width) {
        if (s.length() >= width) return s.substring(0, width);
        return s + " ".repeat(width - s.length());
    }

    private static Path newRunDirectory(AgentConfiguration config) throws IOException {
        Path runDir = config.artifactsDirectory().resolve(
                "run-" + LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss")));
        Files.createDirectories(runDir);
        return runDir;
    }

    private static String parseMode(String[] args) {
        if (args.length == 0) return "start";
        if (args.length == 1 && "--check".equals(args[0])) return "check";
        if (args.length == 1 && "--stop-clean".equals(args[0])) return "stop-clean";
        if (args.length == 1 && "--new".equals(args[0])) return "new";
        if (args.length >= 1 && "--resume".equals(args[0])) return "resume";
        throw new IllegalArgumentException(
                "Usage: java -jar burp-agent-bridge.jar [--check | --stop-clean | --new | --resume]");
    }

    private static Path locateProjectRoot() throws Exception {
        Path current = Path.of("").toAbsolutePath().normalize();
        if (Files.isRegularFile(current.resolve("docker-compose.yml"))) return current;
        Path jar = NativeBurpAgent.runningJar();
        Path candidate = jar.getParent();
        if (candidate != null) candidate = candidate.getParent();
        if (candidate != null) candidate = candidate.getParent();
        if (candidate != null && Files.isRegularFile(candidate.resolve("docker-compose.yml")))
            return candidate;
        throw new IllegalStateException("Run the agent from the project root");
    }

    @SuppressWarnings("unused")
    private static Path resolveResumeDirectory(Path artifactsDir, String[] args) throws IOException {
        if (args.length >= 2) {
            Path explicit = artifactsDir.resolve(args[1]);
            if (Files.isDirectory(explicit) && Files.exists(explicit.resolve("burp-project.burp")))
                return explicit;
            throw new IllegalArgumentException(
                    "Specified run directory or burp-project.burp not found: " + explicit);
        }
        try (Stream<Path> stream = Files.list(artifactsDir)) {
            return stream
                    .filter(Files::isDirectory)
                    .filter(p -> p.getFileName().toString().startsWith("run-"))
                    .filter(p -> Files.exists(p.resolve("burp-project.burp")))
                    .filter(p -> {
                        try { return Files.size(p.resolve("burp-project.burp")) > 0; }
                        catch (IOException e) { return false; }
                    })
                    .max(Comparator.comparing(Path::getFileName))
                    .orElseThrow(() -> new IOException(
                            "No valid previous run directory with burp-project.burp found in " + artifactsDir));
        }
    }
}
