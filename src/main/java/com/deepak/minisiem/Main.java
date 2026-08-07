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

        // Create application components
        LogReader logReader = new LogReader();
        LogParser logParser = new LogParser();
        EventStore eventStore = new EventStore();
        AlertStore alertStore = new AlertStore();
        DetectionEngine detectionEngine = new DetectionEngine();
        DatabaseManager databaseManager = new DatabaseManager();

        // Create SQLite tables if they do not already exist
        databaseManager.createTables();

        // Read authentication log file
        List<String> logLines = logReader.readLogFile();

        // Parse, store in memory, and save events to SQLite
        for (String line : logLines) {

            SecurityEvent event = logParser.parse(line);

            // Store in RAM
            eventStore.addEvent(event);

            // Store permanently in SQLite
            databaseManager.saveEvent(event);
        }

        System.out.println(
                "Total Events Loaded: " + eventStore.getEventCount()
        );

        // Run all detection algorithms
        List<SecurityAlert> detectedAlerts =
                detectionEngine.detect(eventStore.getEvents());

        // Store detected alerts in memory
        for (SecurityAlert alert : detectedAlerts) {
            alertStore.addAlert(alert);
        }

        System.out.println(
                "Total Alerts: " + alertStore.getAlertCount()
        );

        // Display security alerts
        for (SecurityAlert alert : alertStore.getAlerts()) {

            System.out.println();
            System.out.println("===== SECURITY ALERT =====");
            System.out.println("Type      : " + alert.getAlertType());
            System.out.println("Severity  : " + alert.getSeverity());
            System.out.println("Username  : " + alert.getUsername());
            System.out.println("IP Address: " + alert.getIpAddress());
            System.out.println("Message   : " + alert.getMessage());
        }
    }
}