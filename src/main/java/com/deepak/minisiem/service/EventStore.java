package com.deepak.minisiem.service;

import com.deepak.minisiem.model.SecurityEvent;

import java.util.ArrayList;
import java.util.List;

public class EventStore {

    private final List<SecurityEvent> events = new ArrayList<>();

    public void addEvent(SecurityEvent event) {
        events.add(event);
    }

    public List<SecurityEvent> getEvents() {
        return events;
    }

    public int getEventCount() {
        return events.size();
    }
}