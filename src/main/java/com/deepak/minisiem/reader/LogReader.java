
package com.deepak.minisiem.reader;

import java.io.BufferedReader;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

public class LogReader {

    private static final Path LOG_FILE_PATH =
            Path.of("logs", "authentication.log");

    public List<String> readLogFile() {
        List<String> logLines = new ArrayList<>();

        if (!Files.exists(LOG_FILE_PATH)) {
            System.err.println(
                    "Authentication log file not found: "
                            + LOG_FILE_PATH.toAbsolutePath());
            return logLines;
        }

        if (!Files.isRegularFile(LOG_FILE_PATH)
                || !Files.isReadable(LOG_FILE_PATH)) {
            System.err.println(
                    "Authentication log file is not a readable file: "
                            + LOG_FILE_PATH.toAbsolutePath());
            return logLines;
        }

        try (BufferedReader reader = Files.newBufferedReader(
                LOG_FILE_PATH, StandardCharsets.UTF_8)) {

            String line;

            while ((line = reader.readLine()) != null) {
                if (!line.isBlank()) {
                    logLines.add(line.trim());
                }
            }

        } catch (IOException exception) {
            System.err.println(
                    "Could not read the authentication log file: "
                            + exception.getMessage());
        }

        return logLines;
    }
}
