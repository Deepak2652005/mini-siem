package com.deepak.minisiem.ui;

import com.deepak.minisiem.alert.SecurityAlert;
import com.deepak.minisiem.database.DatabaseManager;
import com.deepak.minisiem.model.SecurityEvent;

import javafx.application.Application;
import javafx.collections.FXCollections;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Scene;
import javafx.scene.control.Label;
import javafx.scene.control.ScrollPane;
import javafx.scene.control.TableColumn;
import javafx.scene.control.TableView;
import javafx.scene.control.cell.PropertyValueFactory;
import javafx.scene.layout.HBox;
import javafx.scene.layout.VBox;
import javafx.stage.Stage;

import java.time.LocalDateTime;
import java.util.List;

public class DashboardApplication extends Application {

    @Override
    public void start(Stage stage) {

        DatabaseManager databaseManager = new DatabaseManager();

        // =========================
        // Load data from SQLite
        // =========================

        int totalEvents = databaseManager.getEventCount();
        int totalAlerts = databaseManager.getAlertCount();

        List<SecurityAlert> alerts =
                databaseManager.getAllAlerts();

        List<SecurityEvent> events =
                databaseManager.getAllEvents();

        long highSeverityAlerts = alerts.stream()
                .filter(alert ->
                        alert.getSeverity().equalsIgnoreCase("HIGH"))
                .count();

        // =========================
        // Dashboard title
        // =========================

        Label title = new Label("MINI SIEM DASHBOARD");

        title.setStyle(
                "-fx-font-size: 28px;" +
                        "-fx-font-weight: bold;"
        );

        // =========================
        // Summary cards
        // =========================

        VBox eventCard = createCard(
                "Total Events",
                String.valueOf(totalEvents)
        );

        VBox alertCard = createCard(
                "Total Alerts",
                String.valueOf(totalAlerts)
        );

        VBox highSeverityCard = createCard(
                "High Severity",
                String.valueOf(highSeverityAlerts)
        );

        HBox cards = new HBox(
                20,
                eventCard,
                alertCard,
                highSeverityCard
        );

        cards.setAlignment(Pos.CENTER);

        // =========================
        // Security Alerts
        // =========================

        Label alertsTitle = new Label("SECURITY ALERTS");

        alertsTitle.setStyle(
                "-fx-font-size: 20px;" +
                        "-fx-font-weight: bold;"
        );

        TableView<SecurityAlert> alertTable =
                createAlertTable(alerts);

        // =========================
        // Security Events
        // =========================

        Label eventsTitle = new Label("SECURITY EVENTS");

        eventsTitle.setStyle(
                "-fx-font-size: 20px;" +
                        "-fx-font-weight: bold;"
        );

        TableView<SecurityEvent> eventTable =
                createEventTable(events);

        // =========================
        // Dashboard content
        // =========================

        VBox content = new VBox(
                30,
                title,
                cards,
                alertsTitle,
                alertTable,
                eventsTitle,
                eventTable
        );

        content.setAlignment(Pos.TOP_CENTER);
        content.setPadding(new Insets(40));

        // Allows dashboard to scroll
        ScrollPane scrollPane = new ScrollPane(content);

        scrollPane.setFitToWidth(true);
        scrollPane.setPannable(true);

        // =========================
        // Scene
        // =========================

        Scene scene = new Scene(
                scrollPane,
                1100,
                750
        );

        stage.setTitle("Mini SIEM Dashboard");
        stage.setScene(scene);

        stage.show();
    }

    // =========================
    // Alert table
    // =========================

    private TableView<SecurityAlert> createAlertTable(
            List<SecurityAlert> alerts) {

        TableView<SecurityAlert> table =
                new TableView<>();

        TableColumn<SecurityAlert, String> typeColumn =
                new TableColumn<>("Type");

        typeColumn.setCellValueFactory(
                new PropertyValueFactory<>("alertType")
        );

        TableColumn<SecurityAlert, String> severityColumn =
                new TableColumn<>("Severity");

        severityColumn.setCellValueFactory(
                new PropertyValueFactory<>("severity")
        );

        TableColumn<SecurityAlert, String> usernameColumn =
                new TableColumn<>("Username");

        usernameColumn.setCellValueFactory(
                new PropertyValueFactory<>("username")
        );

        TableColumn<SecurityAlert, String> ipColumn =
                new TableColumn<>("IP Address");

        ipColumn.setCellValueFactory(
                new PropertyValueFactory<>("ipAddress")
        );

        TableColumn<SecurityAlert, String> messageColumn =
                new TableColumn<>("Message");

        messageColumn.setCellValueFactory(
                new PropertyValueFactory<>("message")
        );

        table.getColumns().addAll(
                typeColumn,
                severityColumn,
                usernameColumn,
                ipColumn,
                messageColumn
        );

        table.setItems(
                FXCollections.observableArrayList(alerts)
        );

        table.setColumnResizePolicy(
                TableView.CONSTRAINED_RESIZE_POLICY_FLEX_LAST_COLUMN
        );

        table.setPrefHeight(220);

        return table;
    }

    // =========================
    // Event table
    // =========================

    private TableView<SecurityEvent> createEventTable(
            List<SecurityEvent> events) {

        TableView<SecurityEvent> table =
                new TableView<>();

        TableColumn<SecurityEvent, LocalDateTime> timestampColumn =
                new TableColumn<>("Timestamp");

        timestampColumn.setCellValueFactory(
                new PropertyValueFactory<>("timestamp")
        );

        TableColumn<SecurityEvent, String> eventTypeColumn =
                new TableColumn<>("Event Type");

        eventTypeColumn.setCellValueFactory(
                new PropertyValueFactory<>("eventType")
        );

        TableColumn<SecurityEvent, String> usernameColumn =
                new TableColumn<>("Username");

        usernameColumn.setCellValueFactory(
                new PropertyValueFactory<>("username")
        );

        TableColumn<SecurityEvent, String> ipColumn =
                new TableColumn<>("IP Address");

        ipColumn.setCellValueFactory(
                new PropertyValueFactory<>("ipAddress")
        );

        table.getColumns().addAll(
                timestampColumn,
                eventTypeColumn,
                usernameColumn,
                ipColumn
        );

        table.setItems(
                FXCollections.observableArrayList(events)
        );

        table.setColumnResizePolicy(
                TableView.CONSTRAINED_RESIZE_POLICY_FLEX_LAST_COLUMN
        );

        table.setPrefHeight(320);

        return table;
    }

    // =========================
    // Dashboard card
    // =========================

    private VBox createCard(
            String titleText,
            String valueText) {

        Label title = new Label(titleText);
        Label value = new Label(valueText);

        title.setStyle(
                "-fx-font-size: 16px;"
        );

        value.setStyle(
                "-fx-font-size: 32px;" +
                        "-fx-font-weight: bold;"
        );

        VBox card = new VBox(
                10,
                title,
                value
        );

        card.setAlignment(Pos.CENTER);

        card.setPrefSize(
                220,
                120
        );

        card.setStyle(
                "-fx-border-color: #cccccc;" +
                        "-fx-border-radius: 8px;" +
                        "-fx-background-radius: 8px;" +
                        "-fx-padding: 20px;"
        );

        return card;
    }
}