package com.deepak.minisiem.detector;

import com.deepak.minisiem.alert.SecurityAlert;
import com.deepak.minisiem.model.SecurityEvent;

import java.time.Duration;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class PasswordSprayDetector {

    private static final int USER_THRESHOLD = 4;
    private static final long TIME_WINDOW_SECONDS = 120;

    public List<SecurityAlert> detect(List<SecurityEvent> events) {

        Map<String, List<SecurityEvent>> eventsByIp =
                groupFailedEventsByIp(events);

        List<SecurityAlert> alerts = new ArrayList<>();

        for (Map.Entry<String, List<SecurityEvent>> entry
                : eventsByIp.entrySet()) {

            String ipAddress = entry.getKey();
            List<SecurityEvent> failedEvents = entry.getValue();

            failedEvents.sort(
                    Comparator.comparing(SecurityEvent::getTimestamp)
            );

            SecurityAlert alert =
                    detectPasswordSpray(ipAddress, failedEvents);

            if (alert != null) {
                alerts.add(alert);
            }
        }

        return alerts;
    }

    private Map<String, List<SecurityEvent>> groupFailedEventsByIp(
            List<SecurityEvent> events) {

        Map<String, List<SecurityEvent>> eventsByIp =
                new HashMap<>();

        for (SecurityEvent event : events) {

            if (!event.getEventType().equals("LOGIN_FAILED")) {
                continue;
            }

            eventsByIp
                    .computeIfAbsent(
                            event.getIpAddress(),
                            ignoredKey -> new ArrayList<>()
                    )
                    .add(event);
        }

        return eventsByIp;
    }

    private SecurityAlert detectPasswordSpray(
            String ipAddress,
            List<SecurityEvent> events) {

        for (int start = 0; start < events.size(); start++) {

            Set<String> usernames = new HashSet<>();

            for (int end = start; end < events.size(); end++) {

                SecurityEvent firstEvent = events.get(start);
                SecurityEvent currentEvent = events.get(end);

                long seconds = Duration.between(
                        firstEvent.getTimestamp(),
                        currentEvent.getTimestamp()
                ).toSeconds();

                if (seconds > TIME_WINDOW_SECONDS) {
                    break;
                }

                usernames.add(currentEvent.getUsername());

                if (usernames.size() >= USER_THRESHOLD) {

                    return new SecurityAlert(
                            "PASSWORD_SPRAY",
                            "HIGH",
                            "MULTIPLE_USERS",
                            ipAddress,
                            usernames.size()
                                    + " different usernames targeted within "
                                    + seconds
                                    + " seconds."
                    );
                }
            }
        }

        return null;
    }
}