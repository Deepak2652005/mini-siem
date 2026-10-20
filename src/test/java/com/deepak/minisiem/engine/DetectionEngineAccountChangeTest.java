package com.deepak.minisiem.engine;

import com.deepak.minisiem.alert.SecurityAlert;
import com.deepak.minisiem.model.SecurityEvent;
import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertTrue;

class DetectionEngineAccountChangeTest {

    private SecurityEvent event(String type, String username, String details) {
        return new SecurityEvent(
                LocalDateTime.of(2026, 10, 20, 10, 0),
                type,
                username,
                "LOCAL",
                "12345",
                details
        );
    }

    @Test
    void alertsWhenAccountIsCreated() {
        List<SecurityAlert> alerts = new DetectionEngine().detect(
                List.of(event("ACCOUNT_CREATED", "new.user", "Target=new.user"))
        );
        assertTrue(alerts.stream().anyMatch(a ->
                a.getAlertType().equals("ACCOUNT_CREATED")
                        && a.getSeverity().equals("MEDIUM")));
    }

    @Test
    void alertsWhenAccountIsDeleted() {
        List<SecurityAlert> alerts = new DetectionEngine().detect(
                List.of(event("ACCOUNT_DELETED", "former.user", "Target=former.user"))
        );
        assertTrue(alerts.stream().anyMatch(a ->
                a.getAlertType().equals("ACCOUNT_DELETED")
                        && a.getSeverity().equals("MEDIUM")));
    }

    @Test
    void alertsWhenMemberIsAddedToGlobalSecurityGroup() {
        List<SecurityAlert> alerts = new DetectionEngine().detect(
                List.of(event("GLOBAL_GROUP_MEMBER_ADDED", "analyst", "Group=Administrators"))
        );
        assertTrue(alerts.stream().anyMatch(a ->
                a.getAlertType().equals("PRIVILEGED_GROUP_CHANGE")
                        && a.getSeverity().equals("HIGH")
                        && a.getMessage().contains("4728")));
    }

    @Test
    void alertsWhenMemberIsAddedToLocalSecurityGroup() {
        List<SecurityAlert> alerts = new DetectionEngine().detect(
                List.of(event("LOCAL_GROUP_MEMBER_ADDED", "analyst", "Group=Administrators"))
        );
        assertTrue(alerts.stream().anyMatch(a ->
                a.getAlertType().equals("PRIVILEGED_GROUP_CHANGE")
                        && a.getSeverity().equals("HIGH")
                        && a.getMessage().contains("4732")));
    }
}
