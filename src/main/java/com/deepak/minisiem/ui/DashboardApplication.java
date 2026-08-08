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

    @Override
    public void start(Stage stage) {

        DatabaseManager databaseManager =
                new DatabaseManager();

        // =========================
        // Load data from SQLite
        // =========================

        int totalEvents =
                databaseManager.getEventCount();

        int totalAlerts =
                databaseManager.getAlertCount();

        List<SecurityAlert> alerts =
                databaseManager.getAllAlerts();

        List<SecurityEvent> events =
                databaseManager.getAllEvents();

        long highSeverityAlerts = alerts.stream()
                .filter(alert ->
                        alert.getSeverity()
                                .equalsIgnoreCase("HIGH"))
                .count();

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
        // ALERT DATA
        // =========================

        ObservableList<SecurityAlert> alertData =
                FXCollections.observableArrayList(alerts);

        FilteredList<SecurityAlert> filteredAlerts =
                new FilteredList<>(
                        alertData,
                        alert -> true
                );

        // =========================
        // Alert section title
        // =========================

        Label alertsTitle =
                createSectionTitle("SECURITY ALERTS");

        // =========================
        // Alert search
        // =========================

        TextField alertSearchField =
                new TextField();

        alertSearchField.setPromptText(
                "Search alerts by type, username, IP, message..."
        );

        alertSearchField.setPrefWidth(380);
        alertSearchField.setPrefHeight(38);

        // =========================
        // Severity filter
        // =========================

        ComboBox<String> severityFilter =
                new ComboBox<>();

        severityFilter.getItems().addAll(
                "ALL",
                "HIGH",
                "MEDIUM",
                "LOW"
        );

        severityFilter.setValue("ALL");

        severityFilter.setPrefWidth(140);

        // =========================
        // Attack type filter
        // =========================

        ComboBox<String> typeFilter =
                new ComboBox<>();

        typeFilter.getItems().addAll(
                "ALL",
                "BRUTE_FORCE",
                "PASSWORD_SPRAY"
        );

        typeFilter.setValue("ALL");

        typeFilter.setPrefWidth(180);

        // =========================
        // Alert filtering
        // =========================

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

                // Search matching
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

                // Severity matching
                boolean severityMatch =
                        selectedSeverity.equals("ALL")
                                || alert.getSeverity()
                                .equalsIgnoreCase(
                                        selectedSeverity
                                );

                // Attack type matching
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

        // Search listener
        alertSearchField
                .textProperty()
                .addListener(
                        (observable, oldValue, newValue) ->
                                updateAlertFilter.run()
                );

        // Severity listener
        severityFilter
                .valueProperty()
                .addListener(
                        (observable, oldValue, newValue) ->
                                updateAlertFilter.run()
                );

        // Type listener
        typeFilter
                .valueProperty()
                .addListener(
                        (observable, oldValue, newValue) ->
                                updateAlertFilter.run()
                );

        // =========================
        // Alert filter layout
        // =========================

        HBox alertFilters = new HBox(
                15,
                alertSearchField,
                severityFilter,
                typeFilter
        );

        alertFilters.setAlignment(
                Pos.CENTER
        );

        // =========================
        // Alert table
        // =========================

        TableView<SecurityAlert> alertTable =
                createAlertTable(filteredAlerts);

        // =========================
        // EVENT DATA
        // =========================

        ObservableList<SecurityEvent> eventData =
                FXCollections.observableArrayList(events);

        FilteredList<SecurityEvent> filteredEvents =
                new FilteredList<>(
                        eventData,
                        event -> true
                );

        // =========================
        // Event section title
        // =========================

        Label eventsTitle =
                createSectionTitle("SECURITY EVENTS");

        // =========================
        // Event search
        // =========================

        TextField eventSearchField =
                new TextField();

        eventSearchField.setPromptText(
                "Search events by username, IP, event type..."
        );

        eventSearchField.setMaxWidth(500);
        eventSearchField.setPrefHeight(38);

        eventSearchField
                .textProperty()
                .addListener(
                        (observable, oldValue, newValue) -> {

                            String searchText =
                                    newValue
                                            .trim()
                                            .toLowerCase();

                            filteredEvents.setPredicate(
                                    event -> {

                                        if (searchText.isEmpty()) {
                                            return true;
                                        }

                                        return containsIgnoreCase(
                                                event.getUsername(),
                                                searchText
                                        )
                                                || containsIgnoreCase(
                                                event.getIpAddress(),
                                                searchText
                                        )
                                                || containsIgnoreCase(
                                                event.getEventType(),
                                                searchText
                                        )
                                                || containsIgnoreCase(
                                                event.getTimestamp()
                                                        .toString(),
                                                searchText
                                        );
                                    }
                            );
                        }
                );

        // =========================
        // Event table
        // =========================

        TableView<SecurityEvent> eventTable =
                createEventTable(filteredEvents);

        // =========================
        // Main dashboard content
        // =========================

        VBox content = new VBox(
                30,
                title,
                cards,

                alertsTitle,
                alertFilters,
                alertTable,

                eventsTitle,
                eventSearchField,
                eventTable
        );

        content.setAlignment(
                Pos.TOP_CENTER
        );

        content.setPadding(
                new Insets(40)
        );

        // =========================
        // Scroll Pane
        // =========================

        ScrollPane scrollPane =
                new ScrollPane(content);

        scrollPane.setFitToWidth(true);
        scrollPane.setPannable(true);

        // =========================
        // Scene
        // =========================

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
    }

    // =========================
    // Case-insensitive matching
    // =========================

    private boolean containsIgnoreCase(
            String value,
            String searchText) {

        return value != null
                && value.toLowerCase()
                .contains(searchText);
    }

    // =========================
    // Section title
    // =========================

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
    // Alert Table
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
    // Event Table
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
    // Dashboard Card
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