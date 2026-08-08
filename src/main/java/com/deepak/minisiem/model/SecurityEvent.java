package com.deepak.minisiem.model;

import java.time.LocalDateTime;

public class SecurityEvent {

    private final LocalDateTime timestamp;
    private final String eventType;
    private final String username;
    private final String ipAddress;

    private final String sourceEventId;

    // Process path / general event details
    private final String details;

    // Process command line
    private final String commandLine;

    // =========================
    // DEMO LOG CONSTRUCTOR
    // =========================

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
                null,
                null,
                null
        );
    }

    // =========================
    // WINDOWS EVENT
    // NO DETAILS
    // =========================

    public SecurityEvent(
            LocalDateTime timestamp,
            String eventType,
            String username,
            String ipAddress,
            String sourceEventId) {

        this(
                timestamp,
                eventType,
                username,
                ipAddress,
                sourceEventId,
                null,
                null
        );
    }

    // =========================
    // WINDOWS EVENT
    // WITH DETAILS
    // =========================

    public SecurityEvent(
            LocalDateTime timestamp,
            String eventType,
            String username,
            String ipAddress,
            String sourceEventId,
            String details) {

        this(
                timestamp,
                eventType,
                username,
                ipAddress,
                sourceEventId,
                details,
                null
        );
    }

    // =========================
    // FULL CONSTRUCTOR
    // =========================

    public SecurityEvent(
            LocalDateTime timestamp,
            String eventType,
            String username,
            String ipAddress,
            String sourceEventId,
            String details,
            String commandLine) {

        this.timestamp = timestamp;
        this.eventType = eventType;
        this.username = username;
        this.ipAddress = ipAddress;
        this.sourceEventId = sourceEventId;
        this.details = details;
        this.commandLine = commandLine;
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