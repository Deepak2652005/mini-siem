package com.deepak.minisiem.detector;

import com.deepak.minisiem.alert.SecurityAlert;
import com.deepak.minisiem.model.SecurityEvent;

import java.time.Duration;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class BruteForceDetector {

    private static final int FAILED_ATTEMPT_THRESHOLD = 3;
    private static final long TIME_WINDOW_SECONDS = 120;

    public List<SecurityAlert> detect(List<SecurityEvent> events) {

        Map<String, List<SecurityEvent>> groupedEvents =
                groupFailedEvents(events);

        List<SecurityAlert> alerts = new ArrayList<>();

        for (Map.Entry<String, List<SecurityEvent>> entry
                : groupedEvents.entrySet()) {

            String key = entry.getKey();
            List<SecurityEvent> failedEvents = entry.getValue();

            failedEvents.sort(
                    Comparator.comparing(SecurityEvent::getTimestamp)
            );

            SecurityAlert alert =
                    detectSlidingWindow(key, failedEvents);

            if (alert != null) {
                alerts.add(alert);
            }
        }

        return alerts;
    }

    private Map<String, List<SecurityEvent>> groupFailedEvents(
            List<SecurityEvent> events) {

        Map<String, List<SecurityEvent>> groupedEvents =
                new HashMap<>();

        for (SecurityEvent event : events) {

            if (!event.getEventType().equals("LOGIN_FAILED")) {
                continue;
            }

            String key =
                    event.getUsername()
                            + "|"
                            + event.getIpAddress();

            groupedEvents
                    .computeIfAbsent(
                            key,
                            ignoredKey -> new ArrayList<>()
                    )
                    .add(event);
        }

        return groupedEvents;
    }

    private SecurityAlert detectSlidingWindow(
            String key,
            List<SecurityEvent> failedEvents) {

        if (failedEvents.size() < FAILED_ATTEMPT_THRESHOLD) {
            return null;
        }

        for (int startIndex = 0;
             startIndex <= failedEvents.size()
                     - FAILED_ATTEMPT_THRESHOLD;
             startIndex++) {

            int endIndex =
                    startIndex + FAILED_ATTEMPT_THRESHOLD - 1;

            SecurityEvent firstEvent =
                    failedEvents.get(startIndex);

            SecurityEvent lastEvent =
                    failedEvents.get(endIndex);

            long durationSeconds = Duration.between(
                    firstEvent.getTimestamp(),
                    lastEvent.getTimestamp()
            ).toSeconds();

            if (durationSeconds <= TIME_WINDOW_SECONDS) {

                String[] keyParts = key.split("\\|", 2);

                String username = keyParts[0];
                String ipAddress = keyParts[1];

                return createAlert(
                        username,
                        ipAddress,
                        durationSeconds
                );
            }
        }

        return null;
    }

    private SecurityAlert createAlert(
            String username,
            String ipAddress,
            long durationSeconds) {

        String message =
                FAILED_ATTEMPT_THRESHOLD
                        + " failed login attempts detected within "
                        + durationSeconds
                        + " seconds.";

        return new SecurityAlert(
                "BRUTE_FORCE",
                "HIGH",
                username,
                ipAddress,
                message
        );
    }
}