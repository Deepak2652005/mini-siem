package com.deepak.minisiem.alert;

public class SecurityAlert {

    private String alertType;
    private String severity;
    private String username;
    private String ipAddress;
    private String message;

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

    public String getAlertType() {
        return alertType;
    }

    public String getSeverity() {
        return severity;
    }

    public String getUsername() {
        return username;
    }

    public String getIpAddress() {
        return ipAddress;
    }

    public String getMessage() {
        return message;
    }

}