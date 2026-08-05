package com.deepak.minisiem.model;

public class SecurityEvent {

    private String timestamp;
    private String eventType;
    private String username;
    private String ipAddress;

    public SecurityEvent(
            String timestamp,
            String eventType,
            String username,
            String ipAddress) {

        this.timestamp = timestamp;
        this.eventType = eventType;
        this.username = username;
        this.ipAddress = ipAddress;

    }
    public String getTimestamp() {
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