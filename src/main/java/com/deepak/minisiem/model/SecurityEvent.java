package com.deepak.minisiem.model;

import java.time.LocalDateTime;

public class SecurityEvent {

    private final LocalDateTime timestamp;
    private final String eventType;
    private final String username;
    private final String ipAddress;

    // Unique ID from the original event source.
    // Windows events will use EventRecordID.
    // Demo log events can leave this null.
    private final String sourceEventId;

    // Used by your existing demo log code
    public SecurityEvent(
            LocalDateTime timestamp,
            String eventType,
            String username,
            String ipAddress) {

        this(
                timestamp,
                eventType,
                username,
                ipAddress,
                null
        );
    }

    // Used by Windows Event Log
    public SecurityEvent(
            LocalDateTime timestamp,
            String eventType,
            String username,
            String ipAddress,
            String sourceEventId) {

        this.timestamp = timestamp;
        this.eventType = eventType;
        this.username = username;
        this.ipAddress = ipAddress;
        this.sourceEventId = sourceEventId;
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

    public String getSourceEventId() {
        return sourceEventId;
    }
}