
package com.deepak.minisiem.service;

import com.deepak.minisiem.model.SecurityEvent;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

public class EventStore {

    private final List<SecurityEvent> events = new ArrayList<>();

    public void addEvent(SecurityEvent event) {
        events.add(Objects.requireNonNull(
                event,
                "Security event must not be null"
        ));
    }

    public void addEvents(List<SecurityEvent> newEvents) {
        if (newEvents == null || newEvents.isEmpty()) {
            return;
        }

        for (SecurityEvent event : newEvents) {
            addEvent(event);
        }
    }

    public List<SecurityEvent> getEvents() {
        return Collections.unmodifiableList(
                new ArrayList<>(events)
        );
    }

    public int getEventCount() {
        return events.size();
    }

    public void clearEvents() {
        events.clear();
    }
}
