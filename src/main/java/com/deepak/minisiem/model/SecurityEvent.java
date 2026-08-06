package com.deepak.minisiem.model;

import java.time.LocalDateTime;

public class SecurityEvent {

    private final LocalDateTime timestamp;
    private final String eventType;
    private final String username;
    private final String ipAddress;

    public SecurityEvent(
            LocalDateTime timestamp,
            String eventType,
            String username,
            String ipAddress) {

        this.timestamp = timestamp;
        this.eventType = eventType;
        this.username = username;
        this.ipAddress = ipAddress;
    }

    public LocalDateTime getTimestamp() {
        return timestamp;
    }

    public String getEventType() {
        return eventType;
    }

    public String getUsername() {
        return username;
    }

    public String getIpAddress() {
        return ipAddress;
    }
}