
package com.deepak.minisiem.service;

import com.deepak.minisiem.alert.SecurityAlert;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

public class AlertStore {

    private final List<SecurityAlert> alerts = new ArrayList<>();

    public void addAlert(SecurityAlert alert) {
        alerts.add(Objects.requireNonNull(
                alert, "Alert must not be null"
        ));
    }

    public void addAlerts(List<SecurityAlert> newAlerts) {
        if (newAlerts == null || newAlerts.isEmpty()) {
            return;
        }

        for (SecurityAlert alert : newAlerts) {
            addAlert(alert);
        }
    }

    public List<SecurityAlert> getAlerts() {
        return Collections.unmodifiableList(
                new ArrayList<>(alerts)
        );
    }

    public int getAlertCount() {
        return alerts.size();
    }

    public void clearAlerts() {
        alerts.clear();
    }
}
