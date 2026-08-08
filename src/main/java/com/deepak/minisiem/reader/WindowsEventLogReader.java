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

    // =========================
    // READ EVENTS AFTER RECORD ID
    // =========================

    public List<SecurityEvent> readSecurityEventsAfter(
            long lastRecordId) {

        List<SecurityEvent> events =
                new ArrayList<>();

        System.out.println(
                "Last stored Windows RecordId: "
                        + lastRecordId
        );

        String command;

        // First ever import
        if (lastRecordId <= 0) {

            command = """
                    Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624,4625} -MaxEvents 100 |
                    Sort-Object RecordId |
                    ForEach-Object {

                        $xml = [xml]$_.ToXml()
                        $data = @{}

                        foreach ($item in $xml.Event.EventData.Data) {
                            $data[$item.Name] = $item.'#text'
                        }

                        $time = $_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')
                        $id = $_.Id
                        $recordId = $_.RecordId
                        $user = $data['TargetUserName']
                        $ip = $data['IpAddress']

                        $values = @(
                            $time,
                            $id,
                            $recordId,
                            $user,
                            $ip
                        )

                        $output = [string]::Join(
                            [char]124,
                            $values
                        )

                        Write-Output $output
                    }
                    """;

        } else {

            command =
                    "Get-WinEvent "
                            + "-LogName 'Security' "
                            + "-FilterXPath "
                            + "\"*[System["
                            + "((EventID=4624) or (EventID=4625)) "
                            + "and (EventRecordID > "
                            + lastRecordId
                            + ")"
                            + "]]\" "
                            + "-Oldest "
                            + "| ForEach-Object { "
                            + "$xml = [xml]$_.ToXml(); "
                            + "$data = @{}; "
                            + "foreach ($item in $xml.Event.EventData.Data) { "
                            + "$data[$item.Name] = $item.'#text'; "
                            + "} "
                            + "$time = $_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'); "
                            + "$id = $_.Id; "
                            + "$recordId = $_.RecordId; "
                            + "$user = $data['TargetUserName']; "
                            + "$ip = $data['IpAddress']; "
                            + "$values = @($time,$id,$recordId,$user,$ip); "
                            + "$output = [string]::Join([char]124,$values); "
                            + "Write-Output $output; "
                            + "}";
        }

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
            // NORMAL OUTPUT
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

                    SecurityEvent event =
                            parseWindowsEvent(
                                    line
                            );

                    if (event != null) {

                        events.add(event);
                    }
                }
            }

            // =========================
            // ERROR OUTPUT
            // =========================

            StringBuilder errorOutput =
                    new StringBuilder();

            try (BufferedReader errorReader =
                         new BufferedReader(
                                 new InputStreamReader(
                                         process.getErrorStream()
                                 )
                         )) {

                String errorLine;

                while ((errorLine =
                        errorReader.readLine()) != null) {

                    errorOutput
                            .append(errorLine)
                            .append(
                                    System.lineSeparator()
                            );
                }
            }

            int exitCode =
                    process.waitFor();

            if (!errorOutput.isEmpty()) {

                System.out.println(
                        "===== POWERSHELL ERROR ====="
                );

                System.out.println(
                        errorOutput
                );
            }

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
            }

        } catch (Exception exception) {

            System.out.println(
                    "Windows Event Log Java error:"
            );

            exception.printStackTrace();
        }

        // Ensure increasing RecordId order
        events.sort(
                Comparator.comparingLong(
                        event -> Long.parseLong(
                                event.getSourceEventId()
                        )
                )
        );

        System.out.println(
                "New Windows events found: "
                        + events.size()
        );

        if (!events.isEmpty()) {

            SecurityEvent newestEvent =
                    events.get(
                            events.size() - 1
                    );

            System.out.println(
                    "Newest RecordId: "
                            + newestEvent
                            .getSourceEventId()
            );
        }

        return events;
    }

    // =========================
    // PARSE EVENT
    // =========================

    private SecurityEvent parseWindowsEvent(
            String line) {

        try {

            String[] parts =
                    line.split(
                            "\\|",
                            -1
                    );

            if (parts.length < 5) {
                return null;
            }

            String timestampText =
                    parts[0].trim();

            String eventIdText =
                    parts[1].trim();

            String recordId =
                    parts[2].trim();

            String username =
                    parts[3].trim();

            String ipAddress =
                    parts[4].trim();

            int eventId =
                    Integer.parseInt(
                            eventIdText
                    );

            String eventType;

            if (eventId == 4624) {

                eventType =
                        "LOGIN_SUCCESS";

            } else if (eventId == 4625) {

                eventType =
                        "LOGIN_FAILED";

            } else {

                return null;
            }

            if (username.isBlank()
                    || username.equals("-")) {

                username =
                        "UNKNOWN";
            }

            if (ipAddress.isBlank()
                    || ipAddress.equals("-")
                    || ipAddress.equals("::1")
                    || ipAddress.equals(
                    "127.0.0.1"
            )) {

                ipAddress =
                        "LOCAL";
            }

            if (recordId.isBlank()) {
                return null;
            }

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
                    recordId
            );

        } catch (Exception exception) {

            System.out.println(
                    "Could not parse Windows event:"
            );

            System.out.println(line);

            System.out.println(
                    "Reason: "
                            + exception.getMessage()
            );

            return null;
        }
    }
}