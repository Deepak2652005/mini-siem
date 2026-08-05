package com.deepak.minisiem.detector;

import com.deepak.minisiem.model.SecurityEvent;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class BruteForceDetector {

    public void detect(List<SecurityEvent> events) {

        Map<String, Integer> failedAttempts = new HashMap<>();

        for (SecurityEvent event : events) {

            if (event.getEventType().equals("LOGIN_FAILED")) {

                String key =
                        event.getUsername() + "|" + event.getIpAddress();

                int currentCount = failedAttempts.getOrDefault(key, 0);

                failedAttempts.put(key, currentCount + 1);
            }
        }

        for (Map.Entry<String, Integer> entry : failedAttempts.entrySet()) {

            if (entry.getValue() >= 3) {
                System.out.println(
                        "ALERT: Possible brute-force attack detected"
                );
                System.out.println("Target: " + entry.getKey());
                System.out.println(
                        "Failed attempts: " + entry.getValue()
                );
            }
        }
    }
}