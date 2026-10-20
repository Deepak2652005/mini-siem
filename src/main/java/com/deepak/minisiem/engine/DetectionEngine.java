package com.deepak.minisiem.engine;

import com.deepak.minisiem.alert.SecurityAlert;
import com.deepak.minisiem.model.SecurityEvent;

import java.time.Duration;
import java.time.LocalDateTime;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class DetectionEngine {

    private static final int BRUTE_FORCE_THRESHOLD = 3;

    private static final long BRUTE_FORCE_WINDOW_SECONDS = 60;

    private static final int PASSWORD_SPRAY_USER_THRESHOLD = 4;

    private static final long PASSWORD_SPRAY_WINDOW_SECONDS = 60;

    // =========================
    // MAIN DETECTION ENTRY
    // =========================

    public List<SecurityAlert> detect(
            List<SecurityEvent> events) {

        List<SecurityAlert> alerts =
                new ArrayList<>();

        if (events == null || events.isEmpty()) {
            return alerts;
        }

        List<SecurityEvent> sortedEvents =
                new ArrayList<>(events);

        sortedEvents.sort(
                Comparator.comparing(
                        SecurityEvent::getTimestamp
                )
        );

        detectBruteForce(
                sortedEvents,
                alerts
        );

        detectPasswordSpray(
                sortedEvents,
                alerts
        );

        detectSuspiciousProcesses(
                sortedEvents,
                alerts
        );

        detectAccountChanges(
                sortedEvents,
                alerts
        );

        return alerts;
    }

    // =========================
    // BRUTE FORCE
    // =========================

    private void detectBruteForce(
            List<SecurityEvent> events,
            List<SecurityAlert> alerts) {

        for (int i = 0; i < events.size(); i++) {

            SecurityEvent first =
                    events.get(i);

            if (!isFailedLogin(first)) {
                continue;
            }

            String username =
                    first.getUsername();

            String ipAddress =
                    first.getIpAddress();

            LocalDateTime startTime =
                    first.getTimestamp();

            int attempts = 1;

            LocalDateTime lastFailure =
                    startTime;

            for (int j = i + 1;
                 j < events.size();
                 j++) {

                SecurityEvent candidate =
                        events.get(j);

                if (candidate.getTimestamp() == null) {
                    continue;
                }

                long seconds =
                        Duration.between(
                                startTime,
                                candidate.getTimestamp()
                        ).getSeconds();

                if (seconds > BRUTE_FORCE_WINDOW_SECONDS) {
                    break;
                }

                if (!isFailedLogin(candidate)) {
                    continue;
                }

                boolean sameUser =
                        equalsIgnoreCase(
                                username,
                                candidate.getUsername()
                        );

                boolean sameIp =
                        equalsIgnoreCase(
                                ipAddress,
                                candidate.getIpAddress()
                        );

                if (sameUser && sameIp) {

                    attempts++;

                    lastFailure =
                            candidate.getTimestamp();
                }

                if (attempts >= BRUTE_FORCE_THRESHOLD) {

                    long actualWindow =
                            Duration.between(
                                    startTime,
                                    lastFailure
                            ).getSeconds();

                    alerts.add(
                            new SecurityAlert(
                                    "BRUTE_FORCE",
                                    "HIGH",
                                    safe(
                                            username,
                                            "UNKNOWN"
                                    ),
                                    safe(
                                            ipAddress,
                                            "UNKNOWN"
                                    ),
                                    attempts
                                            + " failed login attempts detected within "
                                            + actualWindow
                                            + " seconds."
                            )
                    );

                    break;
                }
            }
        }
    }

    // =========================
    // PASSWORD SPRAY
    // =========================

    private void detectPasswordSpray(
            List<SecurityEvent> events,
            List<SecurityAlert> alerts) {

        for (int i = 0;
             i < events.size();
             i++) {

            SecurityEvent first =
                    events.get(i);

            if (!isFailedLogin(first)) {
                continue;
            }

            String ipAddress =
                    first.getIpAddress();

            LocalDateTime startTime =
                    first.getTimestamp();

            Set<String> usernames =
                    new HashSet<>();

            if (first.getUsername() != null) {

                usernames.add(
                        first.getUsername()
                                .toLowerCase()
                );
            }

            for (int j = i + 1;
                 j < events.size();
                 j++) {

                SecurityEvent candidate =
                        events.get(j);

                if (candidate.getTimestamp() == null) {
                    continue;
                }

                long seconds =
                        Duration.between(
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
                        candidate.getIpAddress()
                )) {
                    continue;
                }

                if (candidate.getUsername() != null) {

                    usernames.add(
                            candidate.getUsername()
                                    .toLowerCase()
                    );
                }

                if (usernames.size()
                        >= PASSWORD_SPRAY_USER_THRESHOLD) {

                    alerts.add(
                            new SecurityAlert(
                                    "PASSWORD_SPRAY",
                                    "HIGH",
                                    "MULTIPLE_USERS",
                                    safe(
                                            ipAddress,
                                            "UNKNOWN"
                                    ),
                                    usernames.size()
                                            + " different usernames targeted within "
                                            + PASSWORD_SPRAY_WINDOW_SECONDS
                                            + " seconds."
                            )
                    );

                    break;
                }
            }
        }
    }

    // =========================
    // ACCOUNT / GROUP CHANGE DETECTION
    // =========================

    private void detectAccountChanges(
            List<SecurityEvent> events,
            List<SecurityAlert> alerts) {

        for (SecurityEvent event : events) {
            if (event == null || event.getEventType() == null) {
                continue;
            }

            String eventType = event.getEventType().toUpperCase();
            String username = safe(event.getUsername(), "UNKNOWN");
            String ipAddress = safe(event.getIpAddress(), "LOCAL");
            String details = safe(event.getDetails(), "");

            switch (eventType) {
                case "ACCOUNT_CREATED" -> alerts.add(new SecurityAlert(
                        "ACCOUNT_CREATED",
                        "MEDIUM",
                        username,
                        ipAddress,
                        "Windows Event ID 4720: user account created. " + details
                ));
                case "ACCOUNT_DELETED" -> alerts.add(new SecurityAlert(
                        "ACCOUNT_DELETED",
                        "MEDIUM",
                        username,
                        ipAddress,
                        "Windows Event ID 4726: user account deleted. " + details
                ));
                case "GLOBAL_GROUP_MEMBER_ADDED" -> alerts.add(new SecurityAlert(
                        "PRIVILEGED_GROUP_CHANGE",
                        "HIGH",
                        username,
                        ipAddress,
                        "Windows Event ID 4728: member added to a security-enabled global group. " + details
                ));
                case "LOCAL_GROUP_MEMBER_ADDED" -> alerts.add(new SecurityAlert(
                        "PRIVILEGED_GROUP_CHANGE",
                        "HIGH",
                        username,
                        ipAddress,
                        "Windows Event ID 4732: member added to a security-enabled local group. " + details
                ));
                default -> {
                    // No account-change rule applies to this event type.
                }
            }
        }
    }

    // =========================
    // PROCESS DETECTION
    // =========================

    private void detectSuspiciousProcesses(
            List<SecurityEvent> events,
            List<SecurityAlert> alerts) {

        for (SecurityEvent event : events) {

            if (event == null) {
                continue;
            }

            if (!"PROCESS_CREATED"
                    .equalsIgnoreCase(
                            event.getEventType()
                    )) {

                continue;
            }

            String processPath =
                    lower(
                            event.getDetails()
                    );

            String commandLine =
                    lower(
                            event.getCommandLine()
                    );

            if (processPath.isBlank()) {
                continue;
            }

            // =========================
            // MINI SIEM COLLECTOR
            // EXCLUSION
            // =========================

            if (isMiniSiemCollector(
                    processPath,
                    commandLine
            )) {

                continue;
            }

            // =========================
            // POWERSHELL ENCODED COMMAND
            // =========================

            if (processPath.contains(
                    "powershell.exe"
            )
                    && containsAny(
                    commandLine,
                    "-encodedcommand",
                    "-enc ",
                    " -e "
            )) {

                createProcessAlert(
                        alerts,
                        event,
                        "SUSPICIOUS_POWERSHELL",
                        "HIGH",
                        "PowerShell encoded command detected."
                );

                continue;
            }

            // =========================
            // EXECUTION POLICY BYPASS
            // =========================

            if (processPath.contains(
                    "powershell.exe"
            )
                    && containsAny(
                    commandLine,
                    "-executionpolicy bypass",
                    "-ep bypass"
            )) {

                createProcessAlert(
                        alerts,
                        event,
                        "SUSPICIOUS_POWERSHELL",
                        "HIGH",
                        "PowerShell execution policy bypass detected."
                );

                continue;
            }

            // =========================
            // HIDDEN POWERSHELL
            // =========================

            if (processPath.contains(
                    "powershell.exe"
            )
                    && containsAny(
                    commandLine,
                    "-windowstyle hidden",
                    "-w hidden"
            )) {

                createProcessAlert(
                        alerts,
                        event,
                        "SUSPICIOUS_POWERSHELL",
                        "HIGH",
                        "Hidden PowerShell execution detected."
                );

                continue;
            }

            // =========================
            // POWERSHELL NETWORK / DOWNLOAD
            // =========================

            if (processPath.contains(
                    "powershell.exe"
            )
                    && containsAny(
                    commandLine,
                    "invoke-webrequest",
                    "iwr ",
                    "downloadstring",
                    "downloadfile"
            )) {

                createProcessAlert(
                        alerts,
                        event,
                        "SUSPICIOUS_POWERSHELL",
                        "HIGH",
                        "PowerShell network/download behavior detected."
                );

                continue;
            }

            // =========================
            // CMD -> POWERSHELL
            // =========================

            if (processPath.contains(
                    "cmd.exe"
            )
                    && commandLine.contains(
                    "powershell"
            )) {

                createProcessAlert(
                        alerts,
                        event,
                        "SUSPICIOUS_COMMAND",
                        "MEDIUM",
                        "Command Prompt launched PowerShell."
                );

                continue;
            }

            // =========================
            // MSHTA REMOTE CONTENT
            // =========================

            if (processPath.contains(
                    "mshta.exe"
            )
                    && containsAny(
                    commandLine,
                    "http://",
                    "https://"
            )) {

                createProcessAlert(
                        alerts,
                        event,
                        "LOLBIN_EXECUTION",
                        "HIGH",
                        "MSHTA launched remote content."
                );

                continue;
            }

            // =========================
            // SCRIPT HOST
            // =========================

            if ((processPath.contains(
                    "wscript.exe"
            )
                    || processPath.contains(
                    "cscript.exe"
            ))
                    && containsAny(
                    commandLine,
                    ".vbs",
                    ".js",
                    ".jse",
                    ".wsf"
            )) {

                createProcessAlert(
                        alerts,
                        event,
                        "SCRIPT_EXECUTION",
                        "MEDIUM",
                        "Windows Script Host executed a script."
                );
            }
        }
    }

    // =========================
    // MINI SIEM COLLECTOR
    // EXCLUSION
    // =========================

    private boolean isMiniSiemCollector(
            String processPath,
            String commandLine) {

        if (processPath == null
                || commandLine == null) {

            return false;
        }

        String process =
                processPath.toLowerCase();

        String command =
                commandLine.toLowerCase();

        // Must actually be PowerShell
        if (!process.contains(
                "powershell.exe"
        )) {

            return false;
        }

        /*
         * Mini SIEM uses PowerShell like:
         *
         * powershell.exe
         * -NoProfile
         * -ExecutionPolicy Bypass
         * -Command
         * Get-WinEvent -FilterHashtable ...
         *
         * This should NOT alert on itself.
         */

        boolean usesGetWinEvent =
                command.contains(
                        "get-winevent"
                );

        boolean usesFilterHashtable =
                command.contains(
                        "filterhashtable"
                );

        return usesGetWinEvent
                && usesFilterHashtable;
    }

    // =========================
    // CREATE PROCESS ALERT
    // =========================

    private void createProcessAlert(
            List<SecurityAlert> alerts,
            SecurityEvent event,
            String alertType,
            String severity,
            String description) {

        String processPath =
                safe(
                        event.getDetails(),
                        "UNKNOWN_PROCESS"
                );

        String commandLine =
                safe(
                        event.getCommandLine(),
                        "NO_COMMAND_LINE"
                );

        String timestamp =
                event.getTimestamp() != null
                        ? event.getTimestamp()
                        .toString()
                        : "UNKNOWN_TIME";

        String message =
                description
                        + " Process: "
                        + processPath
                        + " | Command: "
                        + commandLine
                        + " | Time: "
                        + timestamp;

        alerts.add(
                new SecurityAlert(
                        alertType,
                        severity,
                        safe(
                                event.getUsername(),
                                "UNKNOWN"
                        ),
                        safe(
                                event.getIpAddress(),
                                "LOCAL"
                        ),
                        message
                )
        );
    }

    // =========================
    // HELPERS
    // =========================

    private boolean isFailedLogin(
            SecurityEvent event) {

        return event != null
                && event.getTimestamp() != null
                && "LOGIN_FAILED"
                .equalsIgnoreCase(
                        event.getEventType()
                );
    }

    private boolean equalsIgnoreCase(
            String first,
            String second) {

        return first != null
                && second != null
                && first.equalsIgnoreCase(
                second
        );
    }

    private String safe(
            String value,
            String fallback) {

        if (value == null
                || value.isBlank()) {

            return fallback;
        }

        return value;
    }

    private String lower(
            String value) {

        if (value == null) {
            return "";
        }

        return value.toLowerCase();
    }

    private boolean containsAny(
            String value,
            String... patterns) {

        if (value == null
                || value.isBlank()) {

            return false;
        }

        String lowerValue =
                value.toLowerCase();

        for (String pattern : patterns) {

            if (lowerValue.contains(
                    pattern.toLowerCase()
            )) {

                return true;
            }
        }

        return false;
    }
}