package com.deepak.minisiem.database;

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

    // Create database tables
    public void createTables() {

        String createEventsTable = """
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    username TEXT NOT NULL,
                    ip_address TEXT NOT NULL
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

        try (Connection connection = connect();
             Statement statement = connection.createStatement()) {

            statement.execute(createEventsTable);
            statement.execute(createAlertsTable);

            System.out.println("Database tables initialized.");

        } catch (SQLException exception) {

            System.out.println("Could not create database tables.");
            System.out.println("Reason: " + exception.getMessage());
        }
    }

    // Save one SecurityEvent into SQLite
    public void saveEvent(SecurityEvent event) {

        String sql = """
                INSERT INTO events (
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
}