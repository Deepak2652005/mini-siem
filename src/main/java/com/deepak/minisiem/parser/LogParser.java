
package com.deepak.minisiem.parser;

import com.deepak.minisiem.model.SecurityEvent;
import com.deepak.minisiem.util.DateTimeUtil;

import java.time.LocalDateTime;

public class LogParser {

    public SecurityEvent parse(String line) {
        if (line == null || line.isBlank()) {
            throw new IllegalArgumentException(
                    "Log line must not be null or blank");
        }

        String[] parts = line.trim().split("\\s+");

        if (parts.length < 5) {
            throw new IllegalArgumentException(
                    "Malformed log line: expected at least 5 fields");
        }

        String timestampText = parts[0] + " " + parts[1];
        LocalDateTime timestamp;

        try {
            timestamp = DateTimeUtil.parse(timestampText);
        } catch (RuntimeException exception) {
            throw new IllegalArgumentException(
                    "Malformed log line: invalid timestamp '"
                            + timestampText + "'",
                    exception);
        }

        String eventType = parts[2];
        String username = extractValue(parts[3], "user");
        String ipAddress = extractValue(parts[4], "ip");

        return new SecurityEvent(
                timestamp,
                eventType,
                username,
                ipAddress
        );
    }

    private String extractValue(String field, String expectedKey) {
        int separatorIndex = field.indexOf('=');

        if (separatorIndex <= 0 || separatorIndex == field.length() - 1) {
            throw new IllegalArgumentException(
                    "Malformed log field: " + field);
        }

        String key = field.substring(0, separatorIndex);

        if (!key.equalsIgnoreCase(expectedKey)) {
            throw new IllegalArgumentException(
                    "Expected field '" + expectedKey
                            + "' but found '" + key + "'");
        }

        return field.substring(separatorIndex + 1);
    }
}
