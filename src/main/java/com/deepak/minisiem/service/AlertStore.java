package com.deepak.minisiem.service;

import com.deepak.minisiem.alert.SecurityAlert;

import java.util.ArrayList;
import java.util.List;

public class AlertStore {

    private final List<SecurityAlert> alerts = new ArrayList<>();

    public void addAlert(SecurityAlert alert) {
        alerts.add(alert);
    }

    public List<SecurityAlert> getAlerts() {
        return alerts;
    }

    public int getAlertCount() {
        return alerts.size();
    }

}