
package com.deepak.minisiem.engine;

import com.deepak.minisiem.alert.SecurityAlert;
import com.deepak.minisiem.model.SecurityEvent;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

public class DetectionEngine {

    private static final int BRUTE_FORCE_THRESHOLD = 3;
    private static final long BRUTE_FORCE_WINDOW_SECONDS = 60;

    private static final int PASSWORD_SPRAY_USER_THRESHOLD = 4;
    private static final long PASSWORD_SPRAY_WINDOW_SECONDS = 60;

    // Main detection entry point
    public List<SecurityAlert> detect(List<SecurityEvent> events) {

        List<SecurityAlert> alerts = new ArrayList<>();

        if (events == null || events.isEmpty()) {
            return alerts;
        }

        List<SecurityEvent> sortedEvents = new ArrayList<>();

        for (SecurityEvent event : events) {
            if (event != null && event.getTimestamp() != null) {
                sortedEvents.add(event);
            }
        }

        sortedEvents.sort(
                Comparator.comparing(SecurityEvent::getTimestamp)
        );

        detectBruteForce(sortedEvents, alerts);
        detectPasswordSpray(sortedEvents, alerts);
        detectSuspiciousProcesses(sortedEvents, alerts);

        return alerts;
    }

    // Brute-force detection
    private void detectBruteForce(
            List<SecurityEvent> events,
            List<SecurityAlert> alerts) {

        Set<String> alertedAccounts = new HashSet<>();

        for (int i = 0; i < events.size(); i++) {

            SecurityEvent first = events.get(i);

            if (!isFailedLogin(first)) {
                continue;
            }

            String username = first.getUsername();
            String ipAddress = first.getIpAddress();

            if (username == null || username.isBlank()
                    || ipAddress == null || ipAddress.isBlank()) {
                continue;
            }

            String accountKey =
                    username.toLowerCase(Locale.ROOT)
                            + "|"
                            + ipAddress.toLowerCase(Locale.ROOT);

            if (alertedAccounts.contains(accountKey)) {
                continue;
            }

            LocalDateTime startTime = first.getTimestamp();
            int attempts = 1;
            LocalDateTime lastFailure = startTime;

            for (int j = i + 1; j < events.size(); j++) {

                SecurityEvent candidate = events.get(j);

                long seconds = Duration.between(
                        startTime,
                        candidate.getTimestamp()
                ).getSeconds();

                if (seconds > BRUTE_FORCE_WINDOW_SECONDS) {
                    break;
                }

                if (!isFailedLogin(candidate)) {
                    continue;
                }

                boolean sameUser = equalsIgnoreCase(
                        username,
                        candidate.getUsername()
                );

                boolean sameIp = equalsIgnoreCase(
                        ipAddress,
                        candidate.getIpAddress()
                );

                if (sameUser && sameIp) {
                    attempts++;
                    lastFailure = candidate.getTimestamp();
                }

                if (attempts >= BRUTE_FORCE_THRESHOLD) {

                    long actualWindow = Duration.between(
                            startTime,
                            lastFailure
                    ).getSeconds();

                    alerts.add(
                            new SecurityAlert(
                                    "BRUTE_FORCE",
                                    "HIGH",
                                    username,
                                    ipAddress,
                                    attempts
                                            + " failed login attempts detected within "
                                            + actualWindow
                                            + " seconds."
                            )
                    );

                    alertedAccounts.add(accountKey);
                    break;
                }
            }
        }
    }

    // Password-spray detection
    private void detectPasswordSpray(
            List<SecurityEvent> events,
            List<SecurityAlert> alerts) {

        Set<String> alertedIps = new HashSet<>();

        for (int i = 0; i < events.size(); i++) {

            SecurityEvent first = events.get(i);

            if (!isFailedLogin(first)) {
                continue;
            }

            String ipAddress = first.getIpAddress();

            if (ipAddress == null || ipAddress.isBlank()) {
                continue;
            }

            String ipKey = ipAddress.toLowerCase(Locale.ROOT);

            if (alertedIps.contains(ipKey)) {
                continue;
            }

            LocalDateTime startTime = first.getTimestamp();
            Set<String> usernames = new HashSet<>();

            if (first.getUsername() != null
                    && !first.getUsername().isBlank()) {
                usernames.add(
                        first.getUsername().toLowerCase(Locale.ROOT)
                );
            }

            for (int j = i + 1; j < events.size(); j++) {

                SecurityEvent candidate = events.get(j);

                long seconds = Duration.between(
                        startTime,
                        candidate.getTimestamp()
                ).getSeconds();

                if (seconds > PASSWORD_SPRAY_WINDOW_SECONDS) {
                    break;
                }

                if (!isFailedLogin(candidate)) {
                    continue;
                }

                if (!equalsIgnoreCase(
                        ipAddress,
                        candidate.getIpAddress())) {
                    continue;
                }

                if (candidate.getUsername() != null
                        && !candidate.getUsername().isBlank()) {
                    usernames.add(
                            candidate.getUsername().toLowerCase(Locale.ROOT)
                    );
                }

                if (usernames.size() >= PASSWORD_SPRAY_USER_THRESHOLD) {

                    alerts.add(
                            new SecurityAlert(
                                    "PASSWORD_SPRAY",
                                    "HIGH",
                                    "MULTIPLE_USERS",
                                    ipAddress,
                                    usernames.size()
                                            + " different usernames targeted within "
                                            + PASSWORD_SPRAY_WINDOW_SECONDS
                                            + " seconds."
                            )
                    );

                    alertedIps.add(ipKey);
                    break;
                }
            }
        }
    }

    // Suspicious process detection
    private void detectSuspiciousProcesses(
            List<SecurityEvent> events,
            List<SecurityAlert> alerts) {

        for (SecurityEvent event : events) {

            if (!"PROCESS_CREATED".equalsIgnoreCase(
                    event.getEventType())) {
                continue;
            }

            String processPath = lower(event.getDetails());
            String commandLine = lower(event.getCommandLine());

            if (processPath.isBlank()) {
                continue;
            }

            if (isMiniSiemCollector(processPath, commandLine)) {
                continue;
            }

            if (processPath.contains("powershell.exe")
                    && containsAny(commandLine,
                    "-encodedcommand", "-enc ", " -e ")) {

                createProcessAlert(
                        alerts, event, "SUSPICIOUS_POWERSHELL", "HIGH",
                        "PowerShell encoded command detected."
                );
                continue;
            }

            if (processPath.contains("powershell.exe")
                    && containsAny(commandLine,
                    "-executionpolicy bypass", "-ep bypass")) {

                createProcessAlert(
                        alerts, event, "SUSPICIOUS_POWERSHELL", "HIGH",
                        "PowerShell execution policy bypass detected."
                );
                continue;
            }

            if (processPath.contains("powershell.exe")
                    && containsAny(commandLine,
                    "-windowstyle hidden", "-w hidden")) {

                createProcessAlert(
                        alerts, event, "SUSPICIOUS_POWERSHELL", "HIGH",
                        "Hidden PowerShell execution detected."
                );
                continue;
            }

            if (processPath.contains("powershell.exe")
                    && containsAny(commandLine,
                    "invoke-webrequest", "iwr ",
                    "downloadstring", "downloadfile")) {

                createProcessAlert(
                        alerts, event, "SUSPICIOUS_POWERSHELL", "HIGH",
                        "PowerShell network/download behavior detected."
                );
                continue;
            }

            if (processPath.contains("cmd.exe")
                    && commandLine.contains("powershell")) {

                createProcessAlert(
                        alerts, event, "SUSPICIOUS_COMMAND", "MEDIUM",
                        "Command Prompt launched PowerShell."
                );
                continue;
            }

            if (processPath.contains("mshta.exe")
                    && containsAny(commandLine, "http://", "https://")) {

                createProcessAlert(
                        alerts, event, "LOLBIN_EXECUTION", "HIGH",
                        "MSHTA launched remote content."
                );
                continue;
            }

            if ((processPath.contains("wscript.exe")
                    || processPath.contains("cscript.exe"))
                    && containsAny(commandLine,
                    ".vbs", ".js", ".jse", ".wsf")) {

                createProcessAlert(
                        alerts, event, "SCRIPT_EXECUTION", "MEDIUM",
                        "Windows Script Host executed a script."
                );
            }
        }
    }

    // Exclude the Mini SIEM's own log-collection PowerShell command
    private boolean isMiniSiemCollector(
            String processPath,
            String commandLine) {

        if (processPath == null || commandLine == null) {
            return false;
        }

        if (!processPath.contains("powershell.exe")) {
            return false;
        }

        return commandLine.contains("get-winevent")
                && commandLine.contains("filterhashtable");
    }

    // Create a process-related alert
    private void createProcessAlert(
            List<SecurityAlert> alerts,
            SecurityEvent event,
            String alertType,
            String severity,
            String description) {

        String processPath = safe(
                event.getDetails(),
                "UNKNOWN_PROCESS"
        );

        String commandLine = safe(
                event.getCommandLine(),
                "NO_COMMAND_LINE"
        );

        String timestamp = event.getTimestamp() != null
                ? event.getTimestamp().toString()
                : "UNKNOWN_TIME";

        String message = description
                + " Process: " + processPath
                + " | Command: " + commandLine
                + " | Time: " + timestamp;

        alerts.add(
                new SecurityAlert(
                        alertType,
                        severity,
                        safe(event.getUsername(), "UNKNOWN"),
                        safe(event.getIpAddress(), "LOCAL"),
                        message
                )
        );
    }

    // Helpers
    private boolean isFailedLogin(SecurityEvent event) {
        return event != null
                && event.getTimestamp() != null
                && "LOGIN_FAILED".equalsIgnoreCase(
                event.getEventType()
        );
    }

    private boolean equalsIgnoreCase(String first, String second) {
        return first != null
                && second != null
                && first.equalsIgnoreCase(second);
    }

    private String safe(String value, String fallback) {
        return value == null || value.isBlank()
                ? fallback
                : value;
    }

    private String lower(String value) {
        return value == null
                ? ""
                : value.toLowerCase(Locale.ROOT);
    }

    private boolean containsAny(String value, String... patterns) {
        if (value == null || value.isBlank()) {
            return false;
        }

        String lowerValue = value.toLowerCase(Locale.ROOT);

        for (String pattern : patterns) {
            if (lowerValue.contains(pattern.toLowerCase(Locale.ROOT))) {
                return true;
            }
        }

        return false;
    }
}
