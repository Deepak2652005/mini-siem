package com.deepak.minisiem.detector;

import com.deepak.minisiem.alert.SecurityAlert;
import com.deepak.minisiem.model.SecurityEvent;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class BruteForceDetector {

    private static final int FAILED_ATTEMPT_THRESHOLD = 3;

    public List<SecurityAlert> detect(List<SecurityEvent> events) {

        Map<String, Integer> failedAttempts = new HashMap<>();
        List<SecurityAlert> alerts = new ArrayList<>();

        for (SecurityEvent event : events) {

            if (event.getEventType().equals("LOGIN_FAILED")) {

                String key =
                        event.getUsername() + "|" + event.getIpAddress();

                int currentCount = failedAttempts.getOrDefault(key, 0);

                failedAttempts.put(key, currentCount + 1);
            }
        }

        for (Map.Entry<String, Integer> entry : failedAttempts.entrySet()) {

            int attemptCount = entry.getValue();

            if (attemptCount >= FAILED_ATTEMPT_THRESHOLD) {

                String[] keyParts = entry.getKey().split("\\|", 2);

                String username = keyParts[0];
                String ipAddress = keyParts[1];

                SecurityAlert alert = new SecurityAlert(
                        "BRUTE_FORCE",
                        "HIGH",
                        username,
                        ipAddress,
                        attemptCount + " failed login attempts detected."
                );

                alerts.add(alert);
            }
        }

        return alerts;
    }
}