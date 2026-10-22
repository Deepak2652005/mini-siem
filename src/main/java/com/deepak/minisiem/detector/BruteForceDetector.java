
package com.deepak.minisiem.detector;

import com.deepak.minisiem.alert.SecurityAlert;
import com.deepak.minisiem.model.SecurityEvent;

import java.time.Duration;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

public class BruteForceDetector {

    private static final int FAILED_ATTEMPT_THRESHOLD = 3;
    private static final long TIME_WINDOW_SECONDS = 120;

    public List<SecurityAlert> detect(List<SecurityEvent> events) {
        List<SecurityAlert> alerts = new ArrayList<>();

        if (events == null || events.isEmpty()) {
            return alerts;
        }

        Map<String, List<SecurityEvent>> groupedEvents =
                groupFailedEvents(events);

        for (Map.Entry<String, List<SecurityEvent>> entry
                : groupedEvents.entrySet()) {

            List<SecurityEvent> failedEvents = entry.getValue();

            failedEvents.sort(
                    Comparator.comparing(SecurityEvent::getTimestamp)
            );

            SecurityAlert alert = detectSlidingWindow(
                    entry.getKey(),
                    failedEvents
            );

            if (alert != null) {
                alerts.add(alert);
            }
        }

        return alerts;
    }

    private Map<String, List<SecurityEvent>> groupFailedEvents(
            List<SecurityEvent> events) {

        Map<String, List<SecurityEvent>> groupedEvents = new HashMap<>();

        for (SecurityEvent event : events) {
            if (event == null
                    || event.getEventType() == null
                    || event.getTimestamp() == null) {
                continue;
            }

            if (!"LOGIN_FAILED".equalsIgnoreCase(event.getEventType())) {
                continue;
            }

            String username = normalize(event.getUsername());
            String ipAddress = normalize(event.getIpAddress());

            if (username.isEmpty()
                    || ipAddress.isEmpty()
                    || username.equals("UNKNOWN")
                    || ipAddress.equals("UNKNOWN")) {
                continue;
            }

            String key = username + "|" + ipAddress;

            groupedEvents
                    .computeIfAbsent(key, ignored -> new ArrayList<>())
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
             startIndex <= failedEvents.size() - FAILED_ATTEMPT_THRESHOLD;
             startIndex++) {

            int endIndex = startIndex + FAILED_ATTEMPT_THRESHOLD - 1;

            SecurityEvent firstEvent = failedEvents.get(startIndex);
            SecurityEvent lastEvent = failedEvents.get(endIndex);

            long durationSeconds = Duration.between(
                    firstEvent.getTimestamp(),
                    lastEvent.getTimestamp()
            ).toSeconds();

            if (durationSeconds >= 0
                    && durationSeconds <= TIME_WINDOW_SECONDS) {

                String[] keyParts = key.split("\\|", 2);

                return createAlert(
                        keyParts[0],
                        keyParts[1],
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

        String message = FAILED_ATTEMPT_THRESHOLD
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

    private String normalize(String value) {
        return value == null
                ? ""
                : value.trim().toUpperCase(Locale.ROOT);
    }
}
