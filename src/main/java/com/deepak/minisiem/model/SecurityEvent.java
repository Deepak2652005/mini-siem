package com.deepak.minisiem.model;

import java.time.LocalDateTime;

public class SecurityEvent {

    private final LocalDateTime timestamp;
    private final String eventType;
    private final String username;
    private final String ipAddress;

    // Constructor
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

    // Get event timestamp
    public LocalDateTime getTimestamp() {
        return timestamp;
    }

    // Get event type
    public String getEventType() {
        return eventType;
    }

    // Get username
    public String getUsername() {
        return username;
    }

    // Get IP address
    public String getIpAddress() {
        return ipAddress;
    }
}