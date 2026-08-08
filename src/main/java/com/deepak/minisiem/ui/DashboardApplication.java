package com.deepak.minisiem.ui;

import com.deepak.minisiem.alert.SecurityAlert;
import com.deepak.minisiem.database.DatabaseManager;
import com.deepak.minisiem.engine.DetectionEngine;
import com.deepak.minisiem.model.SecurityEvent;
import com.deepak.minisiem.parser.LogParser;
import com.deepak.minisiem.reader.LogReader;

import javafx.animation.Animation;
import javafx.animation.KeyFrame;
import javafx.animation.Timeline;
import javafx.application.Application;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.collections.transformation.FilteredList;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Scene;
import javafx.scene.chart.PieChart;
import javafx.scene.control.Button;
import javafx.scene.control.ComboBox;
import javafx.scene.control.Label;
import javafx.scene.control.ScrollPane;
import javafx.scene.control.TableCell;
import javafx.scene.control.TableColumn;
import javafx.scene.control.TableView;
import javafx.scene.control.TextField;
import javafx.scene.control.cell.PropertyValueFactory;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.Region;
import javafx.scene.layout.VBox;
import javafx.stage.Stage;
import javafx.util.Duration;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Objects;

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

    private Label clockLabel;
    private Label dateLabel;

    private PieChart eventTypeChart;

    @Override
    public void start(Stage stage) {

        databaseManager.createTables();

        // =========================
        // HEADER
        // =========================

        Label title =
                new Label("MINI SIEM DASHBOARD");

        title.getStyleClass().add(
                "dashboard-title"
        );

        clockLabel =
                new Label();

        dateLabel =
                new Label();

        clockLabel.getStyleClass().add(
                "clock-time"
        );

        dateLabel.getStyleClass().add(
                "clock-date"
        );

        VBox clockBox =
                new VBox(
                        3,
                        clockLabel,
                        dateLabel
                );

        clockBox.setAlignment(
                Pos.CENTER_RIGHT
        );

        Region headerSpacer =
                new Region();

        HBox.setHgrow(
                headerSpacer,
                Priority.ALWAYS
        );

        HBox header =
                new HBox(
                        20,
                        title,
                        headerSpacer,
                        clockBox
                );

        header.setAlignment(
                Pos.CENTER_LEFT
        );

        header.setMaxWidth(
                Double.MAX_VALUE
        );

        startClock();

        // =========================
        // SUMMARY CARDS
        // =========================

        totalEventsValue =
                new Label("0");

        totalAlertsValue =
                new Label("0");

        highSeverityValue =
                new Label("0");

        highSeverityValue
                .getStyleClass()
                .add("high-severity-value");

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

        cards.setAlignment(
                Pos.CENTER
        );

        // =========================
        // REFRESH BUTTON
        // =========================

        Button refreshButton =
                new Button("Refresh");

        refreshButton.setPrefWidth(
                120
        );

        refreshButton.setPrefHeight(
                38
        );

        refreshButton.setOnAction(event -> {

            processLogs();
            refreshData();

        });

        // =========================
        // ALERT SECTION
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

        alertSearchField.setPrefWidth(
                380
        );

        alertSearchField.setPrefHeight(
                38
        );

        ComboBox<String> severityFilter =
                new ComboBox<>();

        severityFilter.getItems().addAll(
                "ALL",
                "HIGH",
                "MEDIUM",
                "LOW"
        );

        severityFilter.setValue(
                "ALL"
        );

        severityFilter.setPrefWidth(
                140
        );

        ComboBox<String> typeFilter =
                new ComboBox<>();

        typeFilter.getItems().addAll(
                "ALL",
                "BRUTE_FORCE",
                "PASSWORD_SPRAY"
        );

        typeFilter.setValue(
                "ALL"
        );

        typeFilter.setPrefWidth(
                180
        );

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
                        selectedSeverity.equals(
                                "ALL"
                        )
                                || alert.getSeverity()
                                .equalsIgnoreCase(
                                        selectedSeverity
                                );

                boolean typeMatch =
                        selectedType.equals(
                                "ALL"
                        )
                                || alert.getAlertType()
                                .equalsIgnoreCase(
                                        selectedType
                                );

                return searchMatch
                        && severityMatch
                        && typeMatch;
            });
        };

        alertSearchField
                .textProperty()
                .addListener(
                        (observable, oldValue, newValue) ->
                                updateAlertFilter.run()
                );

        severityFilter
                .valueProperty()
                .addListener(
                        (observable, oldValue, newValue) ->
                                updateAlertFilter.run()
                );

        typeFilter
                .valueProperty()
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

        alertFilters.setAlignment(
                Pos.CENTER
        );

        TableView<SecurityAlert> alertTable =
                createAlertTable(
                        filteredAlerts
                );

        // =========================
        // EVENT SECTION
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

        eventSearchField.setMaxWidth(
                500
        );

        eventSearchField.setPrefHeight(
                38
        );

        eventSearchField
                .textProperty()
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
                createEventTable(
                        filteredEvents
                );

        // =========================
        // ANALYTICS
        // =========================

        Label analyticsTitle =
                createSectionTitle(
                        "ANALYTICS"
                );

        eventTypeChart =
                createEventTypeChart();

        // =========================
        // MAIN LAYOUT
        // =========================

        VBox content =
                new VBox(
                        30,
                        header,
                        cards,
                        refreshButton,

                        alertsTitle,
                        alertFilters,
                        alertTable,

                        eventsTitle,
                        eventSearchField,
                        eventTable,

                        analyticsTitle,
                        eventTypeChart
                );

        content.setPadding(
                new Insets(40)
        );

        content.setAlignment(
                Pos.TOP_CENTER
        );

        ScrollPane scrollPane =
                new ScrollPane(
                        content
                );

        scrollPane.setFitToWidth(
                true
        );

        scrollPane.setPannable(
                true
        );

        Scene scene =
                new Scene(
                        scrollPane,
                        1100,
                        750
                );

        scene.getStylesheets().add(
                Objects.requireNonNull(
                        getClass()
                                .getResource(
                                        "/dashboard.css"
                                )
                ).toExternalForm()
        );

        stage.setTitle(
                "Mini SIEM Dashboard"
        );

        stage.setScene(
                scene
        );

        stage.show();

        refreshData();
    }

    // =========================
    // REAL-TIME CLOCK
    // =========================

    private void startClock() {

        updateClock();

        Timeline timeline =
                new Timeline(
                        new KeyFrame(
                                Duration.seconds(1),
                                event ->
                                        updateClock()
                        )
                );

        timeline.setCycleCount(
                Animation.INDEFINITE
        );

        timeline.play();
    }

    private void updateClock() {

        LocalDateTime now =
                LocalDateTime.now();

        DateTimeFormatter timeFormatter =
                DateTimeFormatter.ofPattern(
                        "hh:mm:ss a"
                );

        DateTimeFormatter dateFormatter =
                DateTimeFormatter.ofPattern(
                        "dd MMM yyyy"
                );

        clockLabel.setText(
                now.format(
                        timeFormatter
                )
        );

        dateLabel.setText(
                now.format(
                        dateFormatter
                )
        );
    }

    // =========================
    // PROCESS LOGS
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
                detectionEngine.detect(
                        events
                );

        for (SecurityAlert alert : detectedAlerts) {

            databaseManager.saveAlert(
                    alert
            );
        }
    }

    // =========================
    // REFRESH DATA
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
                        databaseManager
                                .getEventCount()
                )
        );

        totalAlertsValue.setText(
                String.valueOf(
                        databaseManager
                                .getAlertCount()
                )
        );

        long highSeverityCount =
                alertData.stream()
                        .filter(alert ->
                                alert.getSeverity()
                                        .equalsIgnoreCase(
                                                "HIGH"
                                        )
                        )
                        .count();

        highSeverityValue.setText(
                String.valueOf(
                        highSeverityCount
                )
        );

        updateEventTypeChart();
    }

    // =========================
    // EVENT TYPE CHART
    // =========================

    private void updateEventTypeChart() {

        long loginSuccessCount =
                eventData.stream()
                        .filter(event ->
                                event.getEventType()
                                        .equalsIgnoreCase(
                                                "LOGIN_SUCCESS"
                                        )
                        )
                        .count();

        long loginFailedCount =
                eventData.stream()
                        .filter(event ->
                                event.getEventType()
                                        .equalsIgnoreCase(
                                                "LOGIN_FAILED"
                                        )
                        )
                        .count();

        ObservableList<PieChart.Data> chartData =
                FXCollections.observableArrayList();

        if (loginSuccessCount > 0) {

            chartData.add(
                    new PieChart.Data(
                            "LOGIN_SUCCESS ("
                                    + loginSuccessCount
                                    + ")",
                            loginSuccessCount
                    )
            );
        }

        if (loginFailedCount > 0) {

            chartData.add(
                    new PieChart.Data(
                            "LOGIN_FAILED ("
                                    + loginFailedCount
                                    + ")",
                            loginFailedCount
                    )
            );
        }

        eventTypeChart.setData(
                chartData
        );
    }

    private PieChart createEventTypeChart() {

        PieChart chart =
                new PieChart();

        chart.setTitle(
                "Event Types"
        );

        chart.setLabelsVisible(
                true
        );

        chart.setLegendVisible(
                true
        );

        chart.setPrefSize(
                500,
                350
        );

        return chart;
    }

    // =========================
    // UTILITIES
    // =========================

    private boolean containsIgnoreCase(
            String value,
            String searchText) {

        return value != null
                && value
                .toLowerCase()
                .contains(
                        searchText
                );
    }

    private Label createSectionTitle(
            String text) {

        Label label =
                new Label(
                        text
                );

        label.getStyleClass().add(
                "section-title"
        );

        return label;
    }

    // =========================
    // ALERT TABLE
    // =========================

    private TableView<SecurityAlert> createAlertTable(
            ObservableList<SecurityAlert> alerts) {

        TableView<SecurityAlert> table =
                new TableView<>();

        TableColumn<SecurityAlert, String> typeColumn =
                new TableColumn<>(
                        "Type"
                );

        typeColumn.setCellValueFactory(
                new PropertyValueFactory<>(
                        "alertType"
                )
        );

        TableColumn<SecurityAlert, String> severityColumn =
                new TableColumn<>(
                        "Severity"
                );

        severityColumn.setCellValueFactory(
                new PropertyValueFactory<>(
                        "severity"
                )
        );

        severityColumn.setCellFactory(
                column ->
                        new TableCell<>() {

                            @Override
                            protected void updateItem(
                                    String severity,
                                    boolean empty) {

                                super.updateItem(
                                        severity,
                                        empty
                                );

                                if (empty || severity == null) {

                                    setText(null);
                                    setStyle("");

                                    return;
                                }

                                setText(
                                        severity
                                );

                                switch (
                                        severity.toUpperCase()
                                ) {

                                    case "HIGH" ->
                                            setStyle(
                                                    "-fx-text-fill: #ef4444;" +
                                                            "-fx-font-weight: bold;"
                                            );

                                    case "MEDIUM" ->
                                            setStyle(
                                                    "-fx-text-fill: #f59e0b;" +
                                                            "-fx-font-weight: bold;"
                                            );

                                    case "LOW" ->
                                            setStyle(
                                                    "-fx-text-fill: #22c55e;" +
                                                            "-fx-font-weight: bold;"
                                            );

                                    default ->
                                            setStyle(
                                                    "-fx-text-fill: #e2e8f0;"
                                            );
                                }
                            }
                        }
        );

        TableColumn<SecurityAlert, String> usernameColumn =
                new TableColumn<>(
                        "Username"
                );

        usernameColumn.setCellValueFactory(
                new PropertyValueFactory<>(
                        "username"
                )
        );

        TableColumn<SecurityAlert, String> ipColumn =
                new TableColumn<>(
                        "IP Address"
                );

        ipColumn.setCellValueFactory(
                new PropertyValueFactory<>(
                        "ipAddress"
                )
        );

        TableColumn<SecurityAlert, String> messageColumn =
                new TableColumn<>(
                        "Message"
                );

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

        table.setItems(
                alerts
        );

        table.setColumnResizePolicy(
                TableView
                        .CONSTRAINED_RESIZE_POLICY_FLEX_LAST_COLUMN
        );

        table.setPrefHeight(
                220
        );

        return table;
    }

    // =========================
    // EVENT TABLE
    // =========================

    private TableView<SecurityEvent> createEventTable(
            ObservableList<SecurityEvent> events) {

        TableView<SecurityEvent> table =
                new TableView<>();

        TableColumn<SecurityEvent, LocalDateTime> timestampColumn =
                new TableColumn<>(
                        "Timestamp"
                );

        timestampColumn.setCellValueFactory(
                new PropertyValueFactory<>(
                        "timestamp"
                )
        );

        TableColumn<SecurityEvent, String> eventTypeColumn =
                new TableColumn<>(
                        "Event Type"
                );

        eventTypeColumn.setCellValueFactory(
                new PropertyValueFactory<>(
                        "eventType"
                )
        );

        TableColumn<SecurityEvent, String> usernameColumn =
                new TableColumn<>(
                        "Username"
                );

        usernameColumn.setCellValueFactory(
                new PropertyValueFactory<>(
                        "username"
                )
        );

        TableColumn<SecurityEvent, String> ipColumn =
                new TableColumn<>(
                        "IP Address"
                );

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

        table.setItems(
                events
        );

        table.setColumnResizePolicy(
                TableView
                        .CONSTRAINED_RESIZE_POLICY_FLEX_LAST_COLUMN
        );

        table.setPrefHeight(
                320
        );

        return table;
    }

    // =========================
    // DASHBOARD CARD
    // =========================

    private VBox createCard(
            String titleText,
            Label value) {

        Label title =
                new Label(
                        titleText
                );

        title.getStyleClass().add(
                "card-title"
        );

        value.getStyleClass().add(
                "card-value"
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

        card.getStyleClass().add(
                "dashboard-card"
        );

        return card;
    }
}