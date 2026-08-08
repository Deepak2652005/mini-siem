package com.deepak.minisiem.database;

import com.deepak.minisiem.alert.SecurityAlert;
import com.deepak.minisiem.model.SecurityEvent;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Statement;

public class DatabaseManager {

    private static final String DATABASE_URL =
            "jdbc:sqlite:mini-siem.db";

    // Connect to SQLite database
    public Connection connect() {

        try {
            return DriverManager.getConnection(DATABASE_URL);

        } catch (SQLException exception) {

            System.out.println("Database connection failed.");
            System.out.println("Reason: " + exception.getMessage());

            return null;
        }
    }

    // Create tables and unique index
    public void createTables() {

        String createEventsTable = """
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    username TEXT NOT NULL,
                    ip_address TEXT NOT NULL,
                    UNIQUE(timestamp, event_type, username, ip_address)
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
             Statement statement = connection.createStatement()) {

            statement.execute(createEventsTable);
            statement.execute(createAlertsTable);
            statement.execute(createAlertUniqueIndex);

            System.out.println("Database tables initialized.");

        } catch (SQLException exception) {

            System.out.println("Could not create database tables.");
            System.out.println("Reason: " + exception.getMessage());
        }
    }

    // Save one SecurityEvent
    public void saveEvent(SecurityEvent event) {

        String sql = """
                INSERT OR IGNORE INTO events (
                    timestamp,
                    event_type,
                    username,
                    ip_address
                )
                VALUES (?, ?, ?, ?);
                """;

        try (Connection connection = connect();
             PreparedStatement statement =
                     connection.prepareStatement(sql)) {

            statement.setString(
                    1,
                    event.getTimestamp().toString()
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

            statement.executeUpdate();

        } catch (SQLException exception) {

            System.out.println("Could not save security event.");
            System.out.println("Reason: " + exception.getMessage());
        }
    }

    // Save one SecurityAlert
    public void saveAlert(SecurityAlert alert) {

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

            System.out.println("Could not save security alert.");
            System.out.println("Reason: " + exception.getMessage());
        }
    }

    // Count events in database
    public int getEventCount() {

        String sql = "SELECT COUNT(*) FROM events;";

        try (Connection connection = connect();
             Statement statement = connection.createStatement();
             var resultSet = statement.executeQuery(sql)) {

            if (resultSet.next()) {
                return resultSet.getInt(1);
            }

        } catch (SQLException exception) {

            System.out.println("Could not count database events.");
            System.out.println("Reason: " + exception.getMessage());
        }

        return 0;
    }

    // Count alerts in database
    public int getAlertCount() {

        String sql = "SELECT COUNT(*) FROM alerts;";

        try (Connection connection = connect();
             Statement statement = connection.createStatement();
             var resultSet = statement.executeQuery(sql)) {

            if (resultSet.next()) {
                return resultSet.getInt(1);
            }

        } catch (SQLException exception) {

            System.out.println("Could not count database alerts.");
            System.out.println("Reason: " + exception.getMessage());
        }

        return 0;
    }
}