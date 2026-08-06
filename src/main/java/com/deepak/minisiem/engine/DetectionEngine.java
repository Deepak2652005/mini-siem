package com.deepak.minisiem.engine;

import com.deepak.minisiem.alert.SecurityAlert;
import com.deepak.minisiem.detector.BruteForceDetector;
import com.deepak.minisiem.model.SecurityEvent;

import java.util.ArrayList;
import java.util.List;

public class DetectionEngine {

    private final BruteForceDetector bruteForceDetector =
            new BruteForceDetector();

    public List<SecurityAlert> detect(List<SecurityEvent> events) {

        List<SecurityAlert> alerts = new ArrayList<>();

        alerts.addAll(
                bruteForceDetector.detect(events)
        );

        return alerts;
    }
}