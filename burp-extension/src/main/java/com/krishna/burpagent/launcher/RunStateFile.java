package com.krishna.burpagent.launcher;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Comparator;
import java.util.Optional;
import java.util.stream.Stream;

/**
 * Persists and loads lightweight scan-session state so the agent can resume
 * monitoring an existing Burp task after a Ctrl+C or unexpected exit, without
 * starting a brand-new crawl-and-audit.
 *
 * <p>State is written to {@code agent-state.json} inside the run directory.
 * On startup the agent scans {@code artifacts/} for the newest directory that
 * contains both {@code burp-project.burp} and {@code agent-state.json}.
 */
final class RunStateFile {

    static final String STATE_FILENAME = "agent-state.json";
    private static final ObjectMapper JSON = new ObjectMapper();

    private RunStateFile() {}

    // -------------------------------------------------------------------------
    // Public API
    // -------------------------------------------------------------------------

    /**
     * Saves current scan state to {@code runDirectory/agent-state.json}.
     * Silently ignores I/O errors — a missing state file is non-fatal.
     */
    static void save(Path runDirectory, String taskId, String status, int progress) {
        try {
            ObjectNode node = JSON.createObjectNode();
            node.put("taskId", taskId);
            node.put("runDirectory", runDirectory.toAbsolutePath().normalize().toString());
            node.put("lastStatus", status);
            node.put("lastProgress", progress);
            node.put("savedAt", Instant.now().toString());
            Files.writeString(
                    runDirectory.resolve(STATE_FILENAME),
                    JSON.writerWithDefaultPrettyPrinter().writeValueAsString(node));
        } catch (IOException e) {
            System.err.println("[State] Warning: could not save agent state: " + e.getMessage());
        }
    }

    /**
     * Returns the newest run directory under {@code artifactsDir} that has both
     * a non-empty {@code burp-project.burp} and an {@code agent-state.json}.
     * Returns empty if none exists.
     */
    static Optional<RunState> loadLatest(Path artifactsDir) {
        if (!Files.isDirectory(artifactsDir)) return Optional.empty();
        try (Stream<Path> stream = Files.list(artifactsDir)) {
            return stream
                    .filter(Files::isDirectory)
                    .filter(p -> p.getFileName().toString().startsWith("run-"))
                    .filter(p -> Files.exists(p.resolve(STATE_FILENAME)))
                    .filter(p -> hasNonEmptyProjectFile(p))
                    .max(Comparator.comparing(p -> p.getFileName().toString()))
                    .flatMap(dir -> parseQuietly(dir));
        } catch (IOException e) {
            return Optional.empty();
        }
    }

    // -------------------------------------------------------------------------
    // State record
    // -------------------------------------------------------------------------

    record RunState(
            String taskId,
            Path runDirectory,
            String lastStatus,
            int lastProgress,
            Instant savedAt) {

        /** True when enough data is present to attempt task re-attachment. */
        boolean isResumable() {
            return taskId != null && !taskId.isBlank()
                    && runDirectory != null
                    && hasNonEmptyProjectFile(runDirectory);
        }

        /** One-line summary for the interactive prompt. */
        String summaryLine() {
            return String.format("%s  (Task #%s | status: %s | progress: %d%% | saved: %s)",
                    runDirectory.getFileName(), taskId, lastStatus, lastProgress,
                    savedAt.toString().replace("T", " ").substring(0, 19) + " UTC");
        }
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private static boolean hasNonEmptyProjectFile(Path dir) {
        Path projectFile = dir.resolve("burp-project.burp");
        try {
            return Files.exists(projectFile) && Files.size(projectFile) > 0;
        } catch (IOException e) {
            return false;
        }
    }

    private static Optional<RunState> parseQuietly(Path runDir) {
        try {
            JsonNode node = JSON.readTree(runDir.resolve(STATE_FILENAME).toFile());
            String savedRunDir = node.path("runDirectory").asText("");
            Path resolvedDir = savedRunDir.isBlank()
                    ? runDir.toAbsolutePath().normalize()
                    : Path.of(savedRunDir).toAbsolutePath().normalize();
            String savedAtText = node.path("savedAt").asText("");
            Instant savedAt = savedAtText.isBlank() ? Instant.now() : Instant.parse(savedAtText);
            return Optional.of(new RunState(
                    node.path("taskId").asText(""),
                    resolvedDir,
                    node.path("lastStatus").asText("unknown"),
                    node.path("lastProgress").asInt(0),
                    savedAt));
        } catch (Exception e) {
            return Optional.empty();
        }
    }
}
