package com.deepak.minisiem.alert;

public class SecurityAlert {

    private final String alertType;
    private final String severity;
    private final String username;
    private final String ipAddress;
    private final String message;

    // Constructor
    public SecurityAlert(
            String alertType,
            String severity,
            String username,
            String ipAddress,
            String message) {

        this.alertType = alertType;
        this.severity = severity;
        this.username = username;
        this.ipAddress = ipAddress;
        this.message = message;
    }

    // Get alert type
    public String getAlertType() {
        return alertType;
    }

    // Get severity level
    public String getSeverity() {
        return severity;
    }

    // Get affected username
    public String getUsername() {
        return username;
    }

    // Get source IP address
    public String getIpAddress() {
        return ipAddress;
    }

    // Get alert message
    public String getMessage() {
        return message;
    }
}