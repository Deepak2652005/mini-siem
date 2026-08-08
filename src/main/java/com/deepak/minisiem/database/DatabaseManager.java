package com.deepak.minisiem.database;

import com.deepak.minisiem.alert.SecurityAlert;
import com.deepak.minisiem.model.SecurityEvent;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

import java.time.LocalDateTime;

import java.util.ArrayList;
import java.util.List;

public class DatabaseManager {

    private static final String DATABASE_URL =
            "jdbc:sqlite:mini-siem.db";

    // =========================
    // DATABASE CONNECTION
    // =========================

    public Connection connect() {

        try {

            return DriverManager.getConnection(
                    DATABASE_URL
            );

        } catch (SQLException exception) {

            System.out.println(
                    "Database connection failed."
            );

            System.out.println(
                    "Reason: "
                            + exception.getMessage()
            );

            return null;
        }
    }

    // =========================
    // CREATE / UPDATE TABLES
    // =========================

    public void createTables() {

        String createEventsTable = """
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    username TEXT NOT NULL,
                    ip_address TEXT NOT NULL,
                    source_event_id TEXT
                );
                """;

        String createAlertsTable = """
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    alert_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    username TEXT NOT NULL,
                    ip_address TEXT NOT NULL,
                    message TEXT NOT NULL
                );
                """;

        String createAlertUniqueIndex = """
                CREATE UNIQUE INDEX IF NOT EXISTS idx_unique_alert
                ON alerts (
                    alert_type,
                    severity,
                    username,
                    ip_address,
                    message
                );
                """;

        try (Connection connection = connect();
             Statement statement =
                     connection.createStatement()) {

            statement.execute(
                    createEventsTable
            );

            statement.execute(
                    createAlertsTable
            );

            statement.execute(
                    createAlertUniqueIndex
            );

            // Upgrade old database automatically
            addSourceEventIdColumnIfNeeded(
                    connection
            );

            createSourceEventIdIndex(
                    connection
            );

            System.out.println(
                    "Database tables initialized."
            );

        } catch (SQLException exception) {

            System.out.println(
                    "Could not create database tables."
            );

            System.out.println(
                    "Reason: "
                            + exception.getMessage()
            );
        }
    }

    // =========================
    // DATABASE MIGRATION
    // =========================

    private void addSourceEventIdColumnIfNeeded(
            Connection connection)
            throws SQLException {

        boolean columnExists = false;

        String sql =
                "PRAGMA table_info(events);";

        try (Statement statement =
                     connection.createStatement();

             ResultSet resultSet =
                     statement.executeQuery(sql)) {

            while (resultSet.next()) {

                String columnName =
                        resultSet.getString(
                                "name"
                        );

                if ("source_event_id"
                        .equalsIgnoreCase(
                                columnName
                        )) {

                    columnExists = true;
                    break;
                }
            }
        }

        if (!columnExists) {

            System.out.println(
                    "Updating events table..."
            );

            String alterTable = """
                    ALTER TABLE events
                    ADD COLUMN source_event_id TEXT;
                    """;

            try (Statement statement =
                         connection.createStatement()) {

                statement.execute(
                        alterTable
                );
            }

            System.out.println(
                    "source_event_id column added."
            );
        }
    }

    // =========================
    // WINDOWS EVENT UNIQUE INDEX
    // =========================

    private void createSourceEventIdIndex(
            Connection connection)
            throws SQLException {

        /*
         * Only non-null source IDs need to be unique.
         *
         * Demo authentication.log events have NULL
         * source_event_id values.
         */

        String sql = """
                CREATE UNIQUE INDEX IF NOT EXISTS
                idx_unique_source_event
                ON events(source_event_id)
                WHERE source_event_id IS NOT NULL;
                """;

        try (Statement statement =
                     connection.createStatement()) {

            statement.execute(sql);
        }
    }

    // =========================
    // SAVE SECURITY EVENT
    // =========================

    public void saveEvent(
            SecurityEvent event) {

        if (event == null) {
            return;
        }

        /*
         * Windows events:
         * duplicate protection comes from source_event_id.
         *
         * Demo events:
         * source_event_id will be NULL.
         */

        String sql = """
                INSERT OR IGNORE INTO events (
                    timestamp,
                    event_type,
                    username,
                    ip_address,
                    source_event_id
                )
                VALUES (?, ?, ?, ?, ?);
                """;

        try (Connection connection = connect();
             PreparedStatement statement =
                     connection.prepareStatement(sql)) {

            statement.setString(
                    1,
                    event.getTimestamp()
                            .toString()
            );

            statement.setString(
                    2,
                    event.getEventType()
            );

            statement.setString(
                    3,
                    event.getUsername()
            );

            statement.setString(
                    4,
                    event.getIpAddress()
            );

            statement.setString(
                    5,
                    event.getSourceEventId()
            );

            statement.executeUpdate();

        } catch (SQLException exception) {

            System.out.println(
                    "Could not save security event."
            );

            System.out.println(
                    "Reason: "
                            + exception.getMessage()
            );
        }
    }

    // =========================
    // SAVE SECURITY ALERT
    // =========================

    public void saveAlert(
            SecurityAlert alert) {

        if (alert == null) {
            return;
        }

        String sql = """
                INSERT OR IGNORE INTO alerts (
                    alert_type,
                    severity,
                    username,
                    ip_address,
                    message
                )
                VALUES (?, ?, ?, ?, ?);
                """;

        try (Connection connection = connect();
             PreparedStatement statement =
                     connection.prepareStatement(sql)) {

            statement.setString(
                    1,
                    alert.getAlertType()
            );

            statement.setString(
                    2,
                    alert.getSeverity()
            );

            statement.setString(
                    3,
                    alert.getUsername()
            );

            statement.setString(
                    4,
                    alert.getIpAddress()
            );

            statement.setString(
                    5,
                    alert.getMessage()
            );

            statement.executeUpdate();

        } catch (SQLException exception) {

            System.out.println(
                    "Could not save security alert."
            );

            System.out.println(
                    "Reason: "
                            + exception.getMessage()
            );
        }
    }

    // =========================
    // EVENT COUNT
    // =========================

    public int getEventCount() {

        String sql =
                "SELECT COUNT(*) FROM events;";

        try (Connection connection = connect();
             Statement statement =
                     connection.createStatement();
             ResultSet resultSet =
                     statement.executeQuery(sql)) {

            if (resultSet.next()) {

                return resultSet.getInt(1);
            }

        } catch (SQLException exception) {

            System.out.println(
                    "Could not count database events."
            );

            System.out.println(
                    "Reason: "
                            + exception.getMessage()
            );
        }

        return 0;
    }

    // =========================
    // ALERT COUNT
    // =========================

    public int getAlertCount() {

        String sql =
                "SELECT COUNT(*) FROM alerts;";

        try (Connection connection = connect();
             Statement statement =
                     connection.createStatement();
             ResultSet resultSet =
                     statement.executeQuery(sql)) {

            if (resultSet.next()) {

                return resultSet.getInt(1);
            }

        } catch (SQLException exception) {

            System.out.println(
                    "Could not count database alerts."
            );

            System.out.println(
                    "Reason: "
                            + exception.getMessage()
            );
        }

        return 0;
    }

    // =========================
    // LOAD SECURITY EVENTS
    // =========================

    public List<SecurityEvent> getAllEvents() {

        List<SecurityEvent> events =
                new ArrayList<>();

        String sql = """
                SELECT
                    timestamp,
                    event_type,
                    username,
                    ip_address,
                    source_event_id
                FROM events
                ORDER BY timestamp;
                """;

        try (Connection connection = connect();
             Statement statement =
                     connection.createStatement();
             ResultSet resultSet =
                     statement.executeQuery(sql)) {

            while (resultSet.next()) {

                LocalDateTime timestamp =
                        LocalDateTime.parse(
                                resultSet.getString(
                                        "timestamp"
                                )
                        );

                String eventType =
                        resultSet.getString(
                                "event_type"
                        );

                String username =
                        resultSet.getString(
                                "username"
                        );

                String ipAddress =
                        resultSet.getString(
                                "ip_address"
                        );

                String sourceEventId =
                        resultSet.getString(
                                "source_event_id"
                        );

                SecurityEvent event =
                        new SecurityEvent(
                                timestamp,
                                eventType,
                                username,
                                ipAddress,
                                sourceEventId
                        );

                events.add(event);
            }

        } catch (SQLException exception) {

            System.out.println(
                    "Could not load security events."
            );

            System.out.println(
                    "Reason: "
                            + exception.getMessage()
            );
        }

        return events;
    }

    // =========================
    // LOAD SECURITY ALERTS
    // =========================

    public List<SecurityAlert> getAllAlerts() {

        List<SecurityAlert> alerts =
                new ArrayList<>();

        String sql = """
                SELECT
                    alert_type,
                    severity,
                    username,
                    ip_address,
                    message
                FROM alerts
                ORDER BY id;
                """;

        try (Connection connection = connect();
             Statement statement =
                     connection.createStatement();
             ResultSet resultSet =
                     statement.executeQuery(sql)) {

            while (resultSet.next()) {

                String alertType =
                        resultSet.getString(
                                "alert_type"
                        );

                String severity =
                        resultSet.getString(
                                "severity"
                        );

                String username =
                        resultSet.getString(
                                "username"
                        );

                String ipAddress =
                        resultSet.getString(
                                "ip_address"
                        );

                String message =
                        resultSet.getString(
                                "message"
                        );

                SecurityAlert alert =
                        new SecurityAlert(
                                alertType,
                                severity,
                                username,
                                ipAddress,
                                message
                        );

                alerts.add(alert);
            }

        } catch (SQLException exception) {

            System.out.println(
                    "Could not load security alerts."
            );

            System.out.println(
                    "Reason: "
                            + exception.getMessage()
            );
        }

        return alerts;
    }
}