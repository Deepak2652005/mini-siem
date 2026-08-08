package com.deepak.minisiem.reader;

import com.deepak.minisiem.model.SecurityEvent;

import java.io.BufferedReader;
import java.io.InputStreamReader;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

public class WindowsEventLogReader {

    private static final DateTimeFormatter DATE_FORMAT =
            DateTimeFormatter.ofPattern(
                    "yyyy-MM-dd HH:mm:ss"
            );

    private static final int MAX_EVENTS =
            2000;

    // =========================
    // READ NEW WINDOWS EVENTS
    // =========================

    public List<SecurityEvent> readSecurityEventsAfter(
            long lastRecordId) {

        List<SecurityEvent> events =
                new ArrayList<>();

        System.out.println(
                "Last stored Windows RecordId: "
                        + lastRecordId
        );

        // =========================
        // RECORD ID FILTER
        // =========================

        String recordFilter;

        if (lastRecordId <= 0) {

            recordFilter = "";

        } else {

            recordFilter = """
                    Where-Object {
                        $_.RecordId -gt %d
                    } |
                    """.formatted(
                    lastRecordId
            );
        }

        // =========================
        // POWERSHELL COMMAND
        // =========================

        String command = """
                $events = Get-WinEvent `
                    -FilterHashtable @{
                        LogName='Security';
                        Id=4624,4625,4672,4688
                    } `
                    -MaxEvents %d `
                    -ErrorAction SilentlyContinue

                if ($null -eq $events) {
                    exit 0
                }

                $events |
                %s
                Sort-Object RecordId |
                ForEach-Object {

                    $xml = [xml]$_.ToXml()

                    $data = @{}

                    foreach ($item in $xml.Event.EventData.Data) {

                        $data[$item.Name] =
                            $item.'#text'
                    }

                    $time =
                        $_.TimeCreated.ToString(
                            'yyyy-MM-dd HH:mm:ss'
                        )

                    $id =
                        $_.Id

                    $recordId =
                        $_.RecordId

                    // =========================
                    // USERNAME
                    // =========================

                    $user =
                        $data['TargetUserName']

                    if ([string]::IsNullOrWhiteSpace($user)) {

                        $user =
                            $data['SubjectUserName']
                    }

                    if ([string]::IsNullOrWhiteSpace($user)) {

                        $user =
                            $data['AccountName']
                    }

                    // =========================
                    // IP ADDRESS
                    // =========================

                    $ip =
                        $data['IpAddress']

                    // =========================
                    // PROCESS INFORMATION
                    // =========================

                    $details =
                        ''

                    $commandLine =
                        ''

                    if ($id -eq 4688) {

                        $details =
                            $data['NewProcessName']

                        $commandLine =
                            $data['CommandLine']
                    }

                    // =========================
                    // CREATE OUTPUT LINE
                    // =========================

                    $values = @(
                        $time,
                        $id,
                        $recordId,
                        $user,
                        $ip,
                        $details,
                        $commandLine
                    )

                    $output =
                        [string]::Join(
                            [char]124,
                            $values
                        )

                    Write-Output $output
                }
                """.formatted(
                MAX_EVENTS,
                recordFilter
        );

        // =========================
        // START POWERSHELL
        // =========================

        ProcessBuilder processBuilder =
                new ProcessBuilder(
                        "powershell.exe",
                        "-NoProfile",
                        "-ExecutionPolicy",
                        "Bypass",
                        "-Command",
                        command
                );

        try {

            Process process =
                    processBuilder.start();

            // =========================
            // READ NORMAL OUTPUT
            // =========================

            try (BufferedReader reader =
                         new BufferedReader(
                                 new InputStreamReader(
                                         process.getInputStream()
                                 )
                         )) {

                String line;

                while ((line =
                        reader.readLine()) != null) {

                    if (line.isBlank()) {
                        continue;
                    }

                    SecurityEvent event =
                            parseWindowsEvent(
                                    line
                            );

                    if (event != null) {

                        events.add(
                                event
                        );
                    }
                }
            }

            // =========================
            // READ ERROR OUTPUT
            // =========================

            StringBuilder errors =
                    new StringBuilder();

            try (BufferedReader errorReader =
                         new BufferedReader(
                                 new InputStreamReader(
                                         process.getErrorStream()
                                 )
                         )) {

                String line;

                while ((line =
                        errorReader.readLine()) != null) {

                    errors.append(
                                    line
                            )
                            .append(
                                    System.lineSeparator()
                            );
                }
            }

            // =========================
            // WAIT FOR POWERSHELL
            // =========================

            int exitCode =
                    process.waitFor();

            // =========================
            // HANDLE RESULT
            // =========================

            if (exitCode == 0) {

                System.out.println(
                        "Windows Event Log query successful."
                );

            } else {

                System.out.println(
                        "Windows Event Log query failed."
                );

                System.out.println(
                        "PowerShell exit code: "
                                + exitCode
                );

                if (!errors.isEmpty()) {

                    System.out.println(
                            "===== POWERSHELL ERROR ====="
                    );

                    System.out.println(
                            errors
                    );
                }
            }

        } catch (Exception exception) {

            System.out.println(
                    "Windows Event Log Java error:"
            );

            exception.printStackTrace();
        }

        // =========================
        // SORT BY RECORD ID
        // =========================

        events.sort(
                Comparator.comparingLong(
                        event -> {

                            try {

                                return Long.parseLong(
                                        event.getSourceEventId()
                                );

                            } catch (Exception exception) {

                                return 0;
                            }
                        }
                )
        );

        // =========================
        // RESULT INFORMATION
        // =========================

        System.out.println(
                "New Windows events found: "
                        + events.size()
        );

        if (!events.isEmpty()) {

            SecurityEvent latest =
                    events.get(
                            events.size() - 1
                    );

            System.out.println(
                    "Newest RecordId: "
                            + latest.getSourceEventId()
            );

        } else {

            System.out.println(
                    "No new Windows events."
            );
        }

        return events;
    }

    // =========================
    // PARSE WINDOWS EVENT
    // =========================

    private SecurityEvent parseWindowsEvent(
            String line) {

        try {

            String[] parts =
                    line.split(
                            "\\|",
                            -1
                    );

            if (parts.length < 7) {

                return null;
            }

            String timestampText =
                    parts[0].trim();

            int eventId =
                    Integer.parseInt(
                            parts[1].trim()
                    );

            String recordId =
                    parts[2].trim();

            String username =
                    parts[3].trim();

            String ipAddress =
                    parts[4].trim();

            String details =
                    parts[5].trim();

            String commandLine =
                    parts[6].trim();

            // =========================
            // EVENT TYPE
            // =========================

            String eventType;

            switch (eventId) {

                case 4624 ->
                        eventType =
                                "LOGIN_SUCCESS";

                case 4625 ->
                        eventType =
                                "LOGIN_FAILED";

                case 4672 ->
                        eventType =
                                "SPECIAL_PRIVILEGES";

                case 4688 ->
                        eventType =
                                "PROCESS_CREATED";

                default -> {

                    return null;
                }
            }

            // =========================
            // USERNAME CLEANUP
            // =========================

            if (username.isBlank()
                    || "-".equals(username)) {

                username =
                        "UNKNOWN";
            }

            // =========================
            // IP CLEANUP
            // =========================

            if (ipAddress.isBlank()
                    || "-".equals(ipAddress)
                    || "::1".equals(ipAddress)
                    || "127.0.0.1"
                    .equals(ipAddress)) {

                ipAddress =
                        "LOCAL";
            }

            // =========================
            // PROCESS DETAILS
            // =========================

            if (details.isBlank()
                    || "-".equals(details)) {

                details =
                        null;
            }

            if (eventId == 4688
                    && details == null) {

                details =
                        "UNKNOWN_PROCESS";
            }

            // =========================
            // COMMAND LINE
            // =========================

            if (commandLine.isBlank()
                    || "-".equals(commandLine)) {

                commandLine =
                        null;
            }

            // =========================
            // RECORD ID
            // =========================

            if (recordId.isBlank()) {

                return null;
            }

            // =========================
            // TIMESTAMP
            // =========================

            LocalDateTime timestamp =
                    LocalDateTime.parse(
                            timestampText,
                            DATE_FORMAT
                    );

            return new SecurityEvent(
                    timestamp,
                    eventType,
                    username,
                    ipAddress,
                    recordId,
                    details,
                    commandLine
            );

        } catch (Exception exception) {

            System.out.println(
                    "Could not parse Windows event:"
            );

            System.out.println(
                    line
            );

            System.out.println(
                    "Reason: "
                            + exception.getMessage()
            );

            return null;
        }
    }
}