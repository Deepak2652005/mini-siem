package com.deepak.minisiem.reader;

import com.deepak.minisiem.model.SecurityEvent;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;

public class WindowsEventLogReader {

    private static final DateTimeFormatter DATE_FORMAT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    public List<SecurityEvent> readSecurityEvents() {

        List<SecurityEvent> events =
                new ArrayList<>();

        String command = """
                Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624,4625} -MaxEvents 100 |
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
            // NORMAL POWERSHELL OUTPUT
            // =========================

            try (BufferedReader reader =
                         new BufferedReader(
                                 new InputStreamReader(
                                         process.getInputStream()
                                 )
                         )) {

                String line;

                while ((line = reader.readLine()) != null) {

                    SecurityEvent event =
                            parseWindowsEvent(line);

                    if (event != null) {
                        events.add(event);
                    }
                }
            }

            // =========================
            // POWERSHELL ERROR OUTPUT
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

            System.out.println(
                    "PowerShell exit code: "
                            + exitCode
            );

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
                        "Windows Security Event Log read successfully."
                );

            } else {

                System.out.println(
                        "Could not read Windows Security Event Log."
                );
            }

        } catch (Exception exception) {

            System.out.println(
                    "Windows Event Log Java error:"
            );

            exception.printStackTrace();
        }

        System.out.println(
                "Windows security events retrieved: "
                        + events.size()
        );

        return events;
    }

    // =========================
    // PARSE ONE WINDOWS EVENT
    // =========================

    private SecurityEvent parseWindowsEvent(
            String line) {

        try {

            /*
             * Expected PowerShell format:
             *
             * timestamp|eventId|recordId|username|ipAddress
             */

            String[] parts =
                    line.split("\\|", -1);

            if (parts.length < 5) {

                System.out.println(
                        "Invalid Windows event line:"
                );

                System.out.println(line);

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

            // =========================
            // CLEAN USERNAME
            // =========================

            if (username.isBlank()
                    || username.equals("-")) {

                username =
                        "UNKNOWN";
            }

            // =========================
            // CLEAN IP ADDRESS
            // =========================

            if (ipAddress.isBlank()
                    || ipAddress.equals("-")
                    || ipAddress.equals("::1")
                    || ipAddress.equals("127.0.0.1")) {

                ipAddress =
                        "LOCAL";
            }

            // =========================
            // VALIDATE RECORD ID
            // =========================

            if (recordId.isBlank()) {

                System.out.println(
                        "Windows event has no RecordId."
                );

                return null;
            }

            // =========================
            // PARSE TIMESTAMP
            // =========================

            LocalDateTime timestamp =
                    LocalDateTime.parse(
                            timestampText,
                            DATE_FORMAT
                    );

            // =========================
            // CREATE SECURITY EVENT
            // =========================

            return new SecurityEvent(
                    timestamp,
                    eventType,
                    username,
                    ipAddress,
                    recordId
            );

        } catch (Exception exception) {

            System.out.println(
                    "Could not parse Windows event line:"
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