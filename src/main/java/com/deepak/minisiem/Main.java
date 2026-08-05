package com.deepak.minisiem;

import com.deepak.minisiem.alert.SecurityAlert;
import com.deepak.minisiem.detector.BruteForceDetector;
import com.deepak.minisiem.model.SecurityEvent;
import com.deepak.minisiem.parser.LogParser;
import com.deepak.minisiem.reader.LogReader;
import com.deepak.minisiem.service.AlertStore;
import com.deepak.minisiem.service.EventStore;

import java.util.List;

public class Main {

    public static void main(String[] args) {

        System.out.println("===== MINI SIEM =====");

        LogReader logReader = new LogReader();
        LogParser logParser = new LogParser();
        EventStore eventStore = new EventStore();
        AlertStore alertStore = new AlertStore();
        BruteForceDetector bruteForceDetector = new BruteForceDetector();

        List<String> logLines = logReader.readLogFile();

        for (String line : logLines) {

            SecurityEvent event = logParser.parse(line);
            eventStore.addEvent(event);
        }

        System.out.println(
                "Total Events Loaded: " + eventStore.getEventCount()
        );

        List<SecurityAlert> detectedAlerts =
                bruteForceDetector.detect(eventStore.getEvents());

        for (SecurityAlert alert : detectedAlerts) {
            alertStore.addAlert(alert);
        }

        System.out.println(
                "Total Alerts: " + alertStore.getAlertCount()
        );

        for (SecurityAlert alert : alertStore.getAlerts()) {

            System.out.println();
            System.out.println("===== SECURITY ALERT =====");
            System.out.println("Type: " + alert.getAlertType());
            System.out.println("Severity: " + alert.getSeverity());
            System.out.println("Username: " + alert.getUsername());
            System.out.println("IP Address: " + alert.getIpAddress());
            System.out.println("Message: " + alert.getMessage());
        }
    }
}