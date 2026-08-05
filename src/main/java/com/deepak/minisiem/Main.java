package com.deepak.minisiem;

import com.deepak.minisiem.detector.BruteForceDetector;
import com.deepak.minisiem.model.SecurityEvent;
import com.deepak.minisiem.parser.LogParser;
import com.deepak.minisiem.reader.LogReader;
import com.deepak.minisiem.service.EventStore;

import java.util.List;

public class Main {

    public static void main(String[] args) {

        System.out.println("===== MINI SIEM =====");

        LogReader logReader = new LogReader();
        LogParser logParser = new LogParser();
        EventStore eventStore = new EventStore();
        BruteForceDetector bruteForceDetector = new BruteForceDetector();

        List<String> logLines = logReader.readLogFile();

        for (String line : logLines) {
            SecurityEvent event = logParser.parse(line);
            eventStore.addEvent(event);
        }

        System.out.println(
                "Total Events Loaded: " + eventStore.getEventCount()
        );

        bruteForceDetector.detect(eventStore.getEvents());
    }
}