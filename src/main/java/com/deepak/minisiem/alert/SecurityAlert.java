
package com.deepak.minisiem.alert;

import java.util.Objects;

public final class SecurityAlert {

    private final String alertType;
    private final String severity;
    private final String username;
    private final String ipAddress;
    private final String message;

    public SecurityAlert(
            String alertType,
            String severity,
            String username,
            String ipAddress,
            String message) {

        this.alertType = requireText(alertType, "alertType");
        this.severity = validateSeverity(severity);
        this.username = requireText(username, "username");
        this.ipAddress = requireText(ipAddress, "ipAddress");
        this.message = requireText(message, "message");
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

    private static String requireText(String value, String fieldName) {
        Objects.requireNonNull(value, fieldName + " must not be null");

        if (value.isBlank()) {
            throw new IllegalArgumentException(
                    fieldName + " must not be blank"
            );
        }

        return value.trim();
    }

    private static String validateSeverity(String severity) {
        String value = requireText(severity, "severity")
                .toUpperCase(java.util.Locale.ROOT);

        if (!value.equals("LOW")
                && !value.equals("MEDIUM")
                && !value.equals("HIGH")
                && !value.equals("CRITICAL")
                && !value.equals("INFO")) {
            throw new IllegalArgumentException(
                    "Unsupported severity: " + severity
            );
        }

        return value;
    }
}
