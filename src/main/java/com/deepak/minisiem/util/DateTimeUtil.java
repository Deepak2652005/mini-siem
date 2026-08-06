package com.deepak.minisiem.util;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

public class DateTimeUtil {

    private static final DateTimeFormatter FORMATTER =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    public static LocalDateTime parse(String timestamp) {
        return LocalDateTime.parse(timestamp, FORMATTER);
    }
}