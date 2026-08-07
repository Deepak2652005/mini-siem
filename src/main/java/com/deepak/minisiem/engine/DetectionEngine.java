package com.deepak.minisiem.engine;

import com.deepak.minisiem.alert.SecurityAlert;
import com.deepak.minisiem.detector.BruteForceDetector;
import com.deepak.minisiem.detector.PasswordSprayDetector;
import com.deepak.minisiem.model.SecurityEvent;

import java.util.ArrayList;
import java.util.List;

public class DetectionEngine {

    private final BruteForceDetector bruteForceDetector =
            new BruteForceDetector();

    private final PasswordSprayDetector passwordSprayDetector =
            new PasswordSprayDetector();

    public List<SecurityAlert> detect(List<SecurityEvent> events) {

        List<SecurityAlert> alerts = new ArrayList<>();

        alerts.addAll(
                bruteForceDetector.detect(events)
        );

        alerts.addAll(
                passwordSprayDetector.detect(events)
        );

        return alerts;
    }
}