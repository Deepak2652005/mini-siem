package com.deepak.minisiem.parser;

import com.deepak.minisiem.model.SecurityEvent;

public class LogParser {

    public SecurityEvent parse(String line) {

        String[] parts = line.split(" ");

        String timestamp = parts[0] + " " + parts[1];
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