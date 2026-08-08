package com.deepak.minisiem.ui;

import com.deepak.minisiem.alert.SecurityAlert;
import com.deepak.minisiem.database.DatabaseManager;
import com.deepak.minisiem.engine.DetectionEngine;
import com.deepak.minisiem.model.SecurityEvent;
import com.deepak.minisiem.parser.LogParser;
import com.deepak.minisiem.reader.LogReader;

import javafx.application.Application;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.collections.transformation.FilteredList;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.ComboBox;
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

    private final DatabaseManager databaseManager =
            new DatabaseManager();

    private final LogReader logReader =
            new LogReader();

    private final LogParser logParser =
            new LogParser();

    private final DetectionEngine detectionEngine =
            new DetectionEngine();

    private final ObservableList<SecurityAlert> alertData =
            FXCollections.observableArrayList();

    private final ObservableList<SecurityEvent> eventData =
            FXCollections.observableArrayList();

    private Label totalEventsValue;
    private Label totalAlertsValue;
    private Label highSeverityValue;

    @Override
    public void start(Stage stage) {

        databaseManager.createTables();

        // =========================
        // Dashboard title
        // =========================

        Label title =
                new Label("MINI SIEM DASHBOARD");

        title.setStyle(
                "-fx-font-size: 28px;" +
                        "-fx-font-weight: bold;"
        );

        // =========================
        // Summary cards
        // =========================

        totalEventsValue =
                new Label("0");

        totalAlertsValue =
                new Label("0");

        highSeverityValue =
                new Label("0");

        VBox eventCard =
                createCard(
                        "Total Events",
                        totalEventsValue
                );

        VBox alertCard =
                createCard(
                        "Total Alerts",
                        totalAlertsValue
                );

        VBox highSeverityCard =
                createCard(
                        "High Severity",
                        highSeverityValue
                );

        HBox cards =
                new HBox(
                        20,
                        eventCard,
                        alertCard,
                        highSeverityCard
                );

        cards.setAlignment(Pos.CENTER);

        // =========================
        // Refresh button
        // =========================

        Button refreshButton =
                new Button("Refresh");

        refreshButton.setPrefWidth(120);
        refreshButton.setPrefHeight(38);

        refreshButton.setOnAction(event -> {

            processLogs();
            refreshData();

        });

        // =========================
        // ALERT FILTERING
        // =========================

        Label alertsTitle =
                createSectionTitle(
                        "SECURITY ALERTS"
                );

        FilteredList<SecurityAlert> filteredAlerts =
                new FilteredList<>(
                        alertData,
                        alert -> true
                );

        TextField alertSearchField =
                new TextField();

        alertSearchField.setPromptText(
                "Search alerts by type, username, IP, message..."
        );

        alertSearchField.setPrefWidth(380);
        alertSearchField.setPrefHeight(38);

        ComboBox<String> severityFilter =
                new ComboBox<>();

        severityFilter.getItems().addAll(
                "ALL",
                "HIGH",
                "MEDIUM",
                "LOW"
        );

        severityFilter.setValue("ALL");

        ComboBox<String> typeFilter =
                new ComboBox<>();

        typeFilter.getItems().addAll(
                "ALL",
                "BRUTE_FORCE",
                "PASSWORD_SPRAY"
        );

        typeFilter.setValue("ALL");

        Runnable updateAlertFilter = () -> {

            String searchText =
                    alertSearchField
                            .getText()
                            .trim()
                            .toLowerCase();

            String selectedSeverity =
                    severityFilter.getValue();

            String selectedType =
                    typeFilter.getValue();

            filteredAlerts.setPredicate(alert -> {

                boolean searchMatch =
                        searchText.isEmpty()
                                || containsIgnoreCase(
                                alert.getAlertType(),
                                searchText
                        )
                                || containsIgnoreCase(
                                alert.getSeverity(),
                                searchText
                        )
                                || containsIgnoreCase(
                                alert.getUsername(),
                                searchText
                        )
                                || containsIgnoreCase(
                                alert.getIpAddress(),
                                searchText
                        )
                                || containsIgnoreCase(
                                alert.getMessage(),
                                searchText
                        );

                boolean severityMatch =
                        selectedSeverity.equals("ALL")
                                || alert.getSeverity()
                                .equalsIgnoreCase(
                                        selectedSeverity
                                );

                boolean typeMatch =
                        selectedType.equals("ALL")
                                || alert.getAlertType()
                                .equalsIgnoreCase(
                                        selectedType
                                );

                return searchMatch
                        && severityMatch
                        && typeMatch;
            });
        };

        alertSearchField.textProperty()
                .addListener(
                        (observable, oldValue, newValue) ->
                                updateAlertFilter.run()
                );

        severityFilter.valueProperty()
                .addListener(
                        (observable, oldValue, newValue) ->
                                updateAlertFilter.run()
                );

        typeFilter.valueProperty()
                .addListener(
                        (observable, oldValue, newValue) ->
                                updateAlertFilter.run()
                );

        HBox alertFilters =
                new HBox(
                        15,
                        alertSearchField,
                        severityFilter,
                        typeFilter
                );

        alertFilters.setAlignment(Pos.CENTER);

        TableView<SecurityAlert> alertTable =
                createAlertTable(filteredAlerts);

        // =========================
        // EVENT FILTERING
        // =========================

        Label eventsTitle =
                createSectionTitle(
                        "SECURITY EVENTS"
                );

        FilteredList<SecurityEvent> filteredEvents =
                new FilteredList<>(
                        eventData,
                        securityEvent -> true
                );

        TextField eventSearchField =
                new TextField();

        eventSearchField.setPromptText(
                "Search events by username, IP, event type..."
        );

        eventSearchField.setMaxWidth(500);
        eventSearchField.setPrefHeight(38);

        eventSearchField.textProperty()
                .addListener(
                        (observable, oldValue, newValue) -> {

                            String searchText =
                                    newValue
                                            .trim()
                                            .toLowerCase();

                            filteredEvents.setPredicate(
                                    securityEvent -> {

                                        if (searchText.isEmpty()) {
                                            return true;
                                        }

                                        return containsIgnoreCase(
                                                securityEvent.getUsername(),
                                                searchText
                                        )
                                                || containsIgnoreCase(
                                                securityEvent.getIpAddress(),
                                                searchText
                                        )
                                                || containsIgnoreCase(
                                                securityEvent.getEventType(),
                                                searchText
                                        )
                                                || containsIgnoreCase(
                                                securityEvent
                                                        .getTimestamp()
                                                        .toString(),
                                                searchText
                                        );
                                    }
                            );
                        }
                );

        TableView<SecurityEvent> eventTable =
                createEventTable(filteredEvents);

        // =========================
        // Main layout
        // =========================

        VBox content =
                new VBox(
                        30,
                        title,
                        cards,
                        refreshButton,

                        alertsTitle,
                        alertFilters,
                        alertTable,

                        eventsTitle,
                        eventSearchField,
                        eventTable
                );

        content.setAlignment(Pos.TOP_CENTER);

        content.setPadding(
                new Insets(40)
        );

        ScrollPane scrollPane =
                new ScrollPane(content);

        scrollPane.setFitToWidth(true);
        scrollPane.setPannable(true);

        Scene scene =
                new Scene(
                        scrollPane,
                        1100,
                        750
                );

        stage.setTitle(
                "Mini SIEM Dashboard"
        );

        stage.setScene(scene);

        stage.show();

        // Load existing data when dashboard starts
        refreshData();
    }

    // =========================
    // Process authentication log
    // =========================

    private void processLogs() {

        List<String> logLines =
                logReader.readLogFile();

        for (String line : logLines) {

            SecurityEvent securityEvent =
                    logParser.parse(line);

            databaseManager.saveEvent(
                    securityEvent
            );
        }

        List<SecurityEvent> events =
                databaseManager.getAllEvents();

        List<SecurityAlert> detectedAlerts =
                detectionEngine.detect(events);

        for (SecurityAlert alert : detectedAlerts) {

            databaseManager.saveAlert(
                    alert
            );
        }
    }

    // =========================
    // Reload data from SQLite
    // =========================

    private void refreshData() {

        alertData.setAll(
                databaseManager.getAllAlerts()
        );

        eventData.setAll(
                databaseManager.getAllEvents()
        );

        totalEventsValue.setText(
                String.valueOf(
                        databaseManager.getEventCount()
                )
        );

        totalAlertsValue.setText(
                String.valueOf(
                        databaseManager.getAlertCount()
                )
        );

        long highSeverityCount =
                alertData.stream()
                        .filter(alert ->
                                alert.getSeverity()
                                        .equalsIgnoreCase("HIGH"))
                        .count();

        highSeverityValue.setText(
                String.valueOf(
                        highSeverityCount
                )
        );
    }

    // =========================
    // Utility
    // =========================

    private boolean containsIgnoreCase(
            String value,
            String searchText) {

        return value != null
                && value.toLowerCase()
                .contains(searchText);
    }

    private Label createSectionTitle(
            String text) {

        Label label =
                new Label(text);

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
            ObservableList<SecurityAlert> alerts) {

        TableView<SecurityAlert> table =
                new TableView<>();

        TableColumn<SecurityAlert, String> typeColumn =
                new TableColumn<>("Type");

        typeColumn.setCellValueFactory(
                new PropertyValueFactory<>(
                        "alertType"
                )
        );

        TableColumn<SecurityAlert, String> severityColumn =
                new TableColumn<>("Severity");

        severityColumn.setCellValueFactory(
                new PropertyValueFactory<>(
                        "severity"
                )
        );

        TableColumn<SecurityAlert, String> usernameColumn =
                new TableColumn<>("Username");

        usernameColumn.setCellValueFactory(
                new PropertyValueFactory<>(
                        "username"
                )
        );

        TableColumn<SecurityAlert, String> ipColumn =
                new TableColumn<>("IP Address");

        ipColumn.setCellValueFactory(
                new PropertyValueFactory<>(
                        "ipAddress"
                )
        );

        TableColumn<SecurityAlert, String> messageColumn =
                new TableColumn<>("Message");

        messageColumn.setCellValueFactory(
                new PropertyValueFactory<>(
                        "message"
                )
        );

        table.getColumns().addAll(
                typeColumn,
                severityColumn,
                usernameColumn,
                ipColumn,
                messageColumn
        );

        table.setItems(alerts);

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
                new PropertyValueFactory<>(
                        "timestamp"
                )
        );

        TableColumn<SecurityEvent, String> eventTypeColumn =
                new TableColumn<>("Event Type");

        eventTypeColumn.setCellValueFactory(
                new PropertyValueFactory<>(
                        "eventType"
                )
        );

        TableColumn<SecurityEvent, String> usernameColumn =
                new TableColumn<>("Username");

        usernameColumn.setCellValueFactory(
                new PropertyValueFactory<>(
                        "username"
                )
        );

        TableColumn<SecurityEvent, String> ipColumn =
                new TableColumn<>("IP Address");

        ipColumn.setCellValueFactory(
                new PropertyValueFactory<>(
                        "ipAddress"
                )
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
            Label value) {

        Label title =
                new Label(titleText);

        title.setStyle(
                "-fx-font-size: 16px;"
        );

        value.setStyle(
                "-fx-font-size: 32px;" +
                        "-fx-font-weight: bold;"
        );

        VBox card =
                new VBox(
                        10,
                        title,
                        value
                );

        card.setAlignment(
                Pos.CENTER
        );

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