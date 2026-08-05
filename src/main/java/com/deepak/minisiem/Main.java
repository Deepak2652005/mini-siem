package com.deepak.minisiem;

import com.deepak.minisiem.model.SecurityEvent;
import com.deepak.minisiem.parser.LogParser;

public class Main {

    public static void main(String[] args) {

        String logLine =
                "2026-08-05 09:16:11 LOGIN_FAILED user=admin ip=192.168.1.20";

        LogParser logParser = new LogParser();
        SecurityEvent event = logParser.parse(logLine);

        System.out.println("Timestamp: " + event.getTimestamp());
        System.out.println("Event Type: " + event.getEventType());
        System.out.println("Username: " + event.getUsername());
        System.out.println("IP Address: " + event.getIpAddress());
    }
}