
package com.deepak.minisiem.model;

import java.time.LocalDateTime;
import java.util.Objects;

public class SecurityEvent {

    private final LocalDateTime timestamp;
    private final String eventType;
    private final String username;
    private final String ipAddress;
    private final String sourceEventId;
    private final String details;
    private final String commandLine;

    // Demo log constructor
    public SecurityEvent(
            LocalDateTime timestamp,
            String eventType,
            String username,
            String ipAddress) {

        this(timestamp, eventType, username, ipAddress, null, null, null);
    }

    // Windows event without details
    public SecurityEvent(
            LocalDateTime timestamp,
            String eventType,
            String username,
            String ipAddress,
            String sourceEventId) {

        this(timestamp, eventType, username, ipAddress,
                sourceEventId, null, null);
    }

    // Windows event with details
    public SecurityEvent(
            LocalDateTime timestamp,
            String eventType,
            String username,
            String ipAddress,
            String sourceEventId,
            String details) {

        this(timestamp, eventType, username, ipAddress,
                sourceEventId, details, null);
    }

    // Full constructor
    public SecurityEvent(
            LocalDateTime timestamp,
            String eventType,
            String username,
            String ipAddress,
            String sourceEventId,
            String details,
            String commandLine) {

        this.timestamp = Objects.requireNonNull(
                timestamp, "Timestamp must not be null");

        this.eventType = requireText(
                eventType, "Event type must not be blank");

        this.username = normalizeOptional(username);
        this.ipAddress = normalizeOptional(ipAddress);
        this.sourceEventId = normalizeOptional(sourceEventId);
        this.details = normalizeOptional(details);
        this.commandLine = normalizeOptional(commandLine);
    }

    private static String requireText(String value, String message) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(message);
        }
        return value.trim();
    }

    private static String normalizeOptional(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        return value.trim();
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

    public String getDetails() {
        return details;
    }

    public String getCommandLine() {
        return commandLine;
    }
}
