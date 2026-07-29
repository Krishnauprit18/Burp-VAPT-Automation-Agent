package com.krishna.burpagent.launcher;

import java.io.IOException;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.TimeUnit;

final class CommandRunner {
    void run(List<String> command, Path workingDirectory, Duration timeout) throws IOException, InterruptedException {
        Process process = new ProcessBuilder(command)
                .directory(workingDirectory.toFile())
                .inheritIO()
                .start();
        if (!process.waitFor(timeout.toSeconds(), TimeUnit.SECONDS)) {
            process.destroy();
            throw new IOException("Command timed out: " + String.join(" ", command));
        }
        if (process.exitValue() != 0) {
            throw new IOException("Command failed with exit code " + process.exitValue() + ": " + String.join(" ", command));
        }
    }
}
