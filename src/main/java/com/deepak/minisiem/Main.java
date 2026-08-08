package com.deepak.minisiem;

import com.deepak.minisiem.alert.SecurityAlert;
import com.deepak.minisiem.database.DatabaseManager;
import com.deepak.minisiem.engine.DetectionEngine;
import com.deepak.minisiem.model.SecurityEvent;
import com.deepak.minisiem.parser.LogParser;
import com.deepak.minisiem.reader.LogReader;
import com.deepak.minisiem.service.AlertStore;
import com.deepak.minisiem.service.EventStore;

import java.util.List;

public class Main {

    public static void main(String[] args) {

        System.out.println("===== MINI SIEM =====");
        System.out.println(
                "Working directory: " + System.getProperty("user.dir")
        );

        // Create application components
        LogReader logReader = new LogReader();
        LogParser logParser = new LogParser();
        EventStore eventStore = new EventStore();
        AlertStore alertStore = new AlertStore();
        DetectionEngine detectionEngine = new DetectionEngine();
        DatabaseManager databaseManager = new DatabaseManager();

        // Initialize SQLite database tables
        databaseManager.createTables();

        // Read authentication log file
        List<String> logLines = logReader.readLogFile();

        // Parse and store security events
        for (String line : logLines) {

            SecurityEvent event = logParser.parse(line);

            // Store temporarily in RAM
            eventStore.addEvent(event);

            // Store permanently in SQLite
            databaseManager.saveEvent(event);
        }

        System.out.println(
                "Total Events Loaded: " + eventStore.getEventCount()
        );

        // Run all security detectors
        List<SecurityAlert> detectedAlerts =
                detectionEngine.detect(eventStore.getEvents());

        // Store detected alerts
        for (SecurityAlert alert : detectedAlerts) {

            // Store temporarily in RAM
            alertStore.addAlert(alert);

            // Store permanently in SQLite
            databaseManager.saveAlert(alert);
        }

        System.out.println(
                "Total Alerts: " + alertStore.getAlertCount()
        );

        // Display security alerts
        for (SecurityAlert alert : alertStore.getAlerts()) {

            System.out.println();
            System.out.println("===== SECURITY ALERT =====");
            System.out.println(
                    "Type      : " + alert.getAlertType()
            );
            System.out.println(
                    "Severity  : " + alert.getSeverity()
            );
            System.out.println(
                    "Username  : " + alert.getUsername()
            );
            System.out.println(
                    "IP Address: " + alert.getIpAddress()
            );
            System.out.println(
                    "Message   : " + alert.getMessage()
            );
        }

        // Display SQLite database statistics
        System.out.println();
        System.out.println("===== DATABASE =====");

        System.out.println(
                "Events in database: "
                        + databaseManager.getEventCount()
        );

        System.out.println(
                "Alerts in database: "
                        + databaseManager.getAlertCount()
        );
    }
}