
package com.deepak.minisiem.util;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;

public final class DateTimeUtil {

    private static final DateTimeFormatter FORMATTER =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    private DateTimeUtil() {
        // Utility class; prevent instantiation.
    }

    public static LocalDateTime parse(String timestamp) {
        if (timestamp == null || timestamp.isBlank()) {
            throw new IllegalArgumentException(
                    "Timestamp must not be null or blank."
            );
        }

        try {
            return LocalDateTime.parse(timestamp.trim(), FORMATTER);
        } catch (DateTimeParseException exception) {
            throw new IllegalArgumentException(
                    "Invalid timestamp. Expected format: yyyy-MM-dd HH:mm:ss. "
                            + "Received: " + timestamp,
                    exception
            );
        }
    }
}
