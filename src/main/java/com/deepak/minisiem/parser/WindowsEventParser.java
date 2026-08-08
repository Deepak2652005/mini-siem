package com.deepak.minisiem.parser;

import com.deepak.minisiem.model.SecurityEvent;

import java.time.LocalDateTime;

public class WindowsEventParser {

    public SecurityEvent parse(
            String timestamp,
            int eventId,
            String username,
            String ipAddress) {

        String eventType;

        if (eventId == 4624) {

            eventType = "LOGIN_SUCCESS";

        } else if (eventId == 4625) {

            eventType = "LOGIN_FAILED";

        } else {

            return null;
        }

        if (username == null || username.isBlank()) {
            username = "UNKNOWN";
        }

        if (ipAddress == null || ipAddress.isBlank()) {
            ipAddress = "LOCAL";
        }

        return new SecurityEvent(
                LocalDateTime.parse(timestamp),
                eventType,
                username,
                ipAddress
        );
    }
}