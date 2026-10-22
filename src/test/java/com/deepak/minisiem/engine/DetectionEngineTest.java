
package com.deepak.minisiem.engine;

import com.deepak.minisiem.alert.SecurityAlert;
import com.deepak.minisiem.model.SecurityEvent;
import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class DetectionEngineTest {

    private final DetectionEngine detectionEngine = new DetectionEngine();

    @Test
    void emptyEventsShouldReturnNoAlerts() {
        List<SecurityAlert> alerts = detectionEngine.detect(List.of());

        assertTrue(alerts.isEmpty());
    }

    @Test
    void nullEventsShouldReturnNoAlerts() {
        List<SecurityAlert> alerts = detectionEngine.detect(null);

        assertTrue(alerts.isEmpty());
    }

    @Test
    void threeFailedLoginsShouldTriggerBruteForceAlert() {
        LocalDateTime now = LocalDateTime.of(2026, 10, 22, 10, 0);

        List<SecurityEvent> events = List.of(
                failedLogin("deepak", "192.168.1.10", now),
                failedLogin("deepak", "192.168.1.10", now.plusSeconds(10)),
                failedLogin("deepak", "192.168.1.10", now.plusSeconds(20))
        );

        List<SecurityAlert> alerts = detectionEngine.detect(events);

        assertTrue(
                alerts.stream().anyMatch(alert ->
                        "BRUTE_FORCE".equals(alert.getAlertType())),
                "Expected a brute-force alert after three failed logins"
        );
    }

    @Test
    void fourDifferentUsersFromSameIpShouldTriggerPasswordSprayAlert() {
        LocalDateTime now = LocalDateTime.of(2026, 10, 22, 10, 0);

        List<SecurityEvent> events = List.of(
                failedLogin("user1", "192.168.1.20", now),
                failedLogin("user2", "192.168.1.20", now.plusSeconds(5)),
                failedLogin("user3", "192.168.1.20", now.plusSeconds(10)),
                failedLogin("user4", "192.168.1.20", now.plusSeconds(15))
        );

        List<SecurityAlert> alerts = detectionEngine.detect(events);

        assertTrue(
                alerts.stream().anyMatch(alert ->
                        "PASSWORD_SPRAY".equals(alert.getAlertType())),
                "Expected a password-spray alert for four usernames"
        );
    }

    private SecurityEvent failedLogin(
            String username,
            String ipAddress,
            LocalDateTime timestamp) {

        // We'll adjust this constructor if your SecurityEvent class differs.
        return new SecurityEvent(
                timestamp,
                "LOGIN_FAILED",
                username,
                ipAddress,
                "Failed login",
                ""
        );
    }
}
