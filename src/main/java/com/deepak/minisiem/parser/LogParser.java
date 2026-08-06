package com.deepak.minisiem.parser;

import com.deepak.minisiem.model.SecurityEvent;
import com.deepak.minisiem.util.DateTimeUtil;

import java.time.LocalDateTime;

public class LogParser {

    public SecurityEvent parse(String line) {

        String[] parts = line.split(" ");

        String timestampText = parts[0] + " " + parts[1];
        LocalDateTime timestamp = DateTimeUtil.parse(timestampText);

        String eventType = parts[2];
        String username = parts[3].split("=")[1];
        String ipAddress = parts[4].split("=")[1];

        return new SecurityEvent(
                timestamp,
                eventType,
                username,
                ipAddress
        );
    }
}