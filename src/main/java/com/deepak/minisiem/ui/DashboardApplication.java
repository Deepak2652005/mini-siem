package com.deepak.minisiem.ui;

import com.deepak.minisiem.alert.SecurityAlert;
import com.deepak.minisiem.database.DatabaseManager;
import com.deepak.minisiem.model.SecurityEvent;

import javafx.application.Application;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.collections.transformation.FilteredList;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Scene;
import javafx.scene.control.Label;
import javafx.scene.control.ScrollPane;
import javafx.scene.control.TableColumn;
import javafx.scene.control.TableView;
import javafx.scene.control.TextField;
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

        Label alertsTitle =
                createSectionTitle("SECURITY ALERTS");

        TableView<SecurityAlert> alertTable =
                createAlertTable(alerts);

        // =========================
        // Security Events
        // =========================

        Label eventsTitle =
                createSectionTitle("SECURITY EVENTS");

        // Original event data
        ObservableList<SecurityEvent> eventData =
                FXCollections.observableArrayList(events);

        // Filtered version of event data
        FilteredList<SecurityEvent> filteredEvents =
                new FilteredList<>(eventData, event -> true);

        // =========================
        // Search box
        // =========================

        TextField searchField = new TextField();

        searchField.setPromptText(
                "Search by username, IP address, event type..."
        );

        searchField.setMaxWidth(500);

        searchField.setPrefHeight(38);

        // Run whenever user types something
        searchField.textProperty().addListener(
                (observable, oldValue, newValue) -> {

                    String searchText =
                            newValue.trim().toLowerCase();

                    filteredEvents.setPredicate(event -> {

                        // Empty search = show everything
                        if (searchText.isEmpty()) {
                            return true;
                        }

                        boolean usernameMatch =
                                event.getUsername() != null &&
                                        event.getUsername()
                                                .toLowerCase()
                                                .contains(searchText);

                        boolean ipMatch =
                                event.getIpAddress() != null &&
                                        event.getIpAddress()
                                                .toLowerCase()
                                                .contains(searchText);

                        boolean eventTypeMatch =
                                event.getEventType() != null &&
                                        event.getEventType()
                                                .toLowerCase()
                                                .contains(searchText);

                        boolean timestampMatch =
                                event.getTimestamp() != null &&
                                        event.getTimestamp()
                                                .toString()
                                                .toLowerCase()
                                                .contains(searchText);

                        return usernameMatch
                                || ipMatch
                                || eventTypeMatch
                                || timestampMatch;
                    });
                }
        );

        TableView<SecurityEvent> eventTable =
                createEventTable(filteredEvents);

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
                searchField,
                eventTable
        );

        content.setAlignment(Pos.TOP_CENTER);

        content.setPadding(
                new Insets(40)
        );

        // =========================
        // Scroll pane
        // =========================

        ScrollPane scrollPane =
                new ScrollPane(content);

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

        stage.setTitle(
                "Mini SIEM Dashboard"
        );

        stage.setScene(scene);

        stage.show();
    }

    // =========================
    // Create section title
    // =========================

    private Label createSectionTitle(String text) {

        Label label = new Label(text);

        label.setStyle(
                "-fx-font-size: 20px;" +
                        "-fx-font-weight: bold;"
        );

        return label;
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
            ObservableList<SecurityEvent> events) {

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

        table.setItems(events);

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

        Label title =
                new Label(titleText);

        Label value =
                new Label(valueText);

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