package com.deepak.minisiem.reader;

import java.io.BufferedReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

public class LogReader {

    public List<String> readLogFile() {

        List<String> logLines = new ArrayList<>();

        Path logFilePath = Path.of("logs", "authentication.log");

        try (BufferedReader reader = Files.newBufferedReader(logFilePath)) {

            String line;

            while ((line = reader.readLine()) != null) {

                if (!line.isBlank()) {
                    logLines.add(line);
                }

            }

        } catch (IOException exception) {

            System.out.println("Could not read the authentication log file.");
            System.out.println("Reason: " + exception.getMessage());

        }

        return logLines;
    }
}