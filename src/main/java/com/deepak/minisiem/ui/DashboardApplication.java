package com.deepak.minisiem.ui;

import com.deepak.minisiem.alert.SecurityAlert;
import com.deepak.minisiem.database.DatabaseManager;
import com.deepak.minisiem.engine.DetectionEngine;
import com.deepak.minisiem.model.SecurityEvent;
import com.deepak.minisiem.parser.LogParser;
import com.deepak.minisiem.reader.LogReader;
import com.deepak.minisiem.reader.WindowsEventLogReader;

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
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;

public class DashboardApplication extends Application {

    // =========================
    // BACKEND COMPONENTS
    // =========================

    private final DatabaseManager databaseManager =
            new DatabaseManager();

    private final LogReader logReader =
            new LogReader();

    private final WindowsEventLogReader windowsEventLogReader =
            new WindowsEventLogReader();

    private final LogParser logParser =
            new LogParser();

    private final DetectionEngine detectionEngine =
            new DetectionEngine();

    // =========================
    // DASHBOARD DATA
    // =========================

    private final ObservableList<SecurityAlert> alertData =
            FXCollections.observableArrayList();

    private final ObservableList<SecurityEvent> eventData =
            FXCollections.observableArrayList();

    // =========================
    // DASHBOARD COMPONENTS
    // =========================

    private Label totalEventsValue;
    private Label totalAlertsValue;
    private Label highSeverityValue;

    private Label clockLabel;
    private Label dateLabel;

    private PieChart eventTypeChart;
    private PieChart alertTypeChart;

    private Timeline clockTimeline;

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
        // DATA SOURCE + REFRESH
        // =========================

        Label dataSourceLabel =
                new Label("Data Source:");

        ComboBox<String> dataSourceSelector =
                new ComboBox<>();

        dataSourceSelector.getItems().addAll(
                "Demo Log File",
                "Windows Event Log"
        );

        dataSourceSelector.setValue(
                "Demo Log File"
        );

        dataSourceSelector.setPrefWidth(
                190
        );

        Button refreshButton =
                new Button("Refresh");

        refreshButton.setPrefWidth(
                120
        );

        refreshButton.setPrefHeight(
                38
        );

        refreshButton.setOnAction(event -> {

            String selectedSource =
                    dataSourceSelector.getValue();

            if ("Windows Event Log"
                    .equals(selectedSource)) {

                processWindowsEvents();

            } else {

                processLogs();
            }

            refreshData();
        });

        HBox dataSourceControls =
                new HBox(
                        15,
                        dataSourceLabel,
                        dataSourceSelector,
                        refreshButton
                );

        dataSourceControls.setAlignment(
                Pos.CENTER
        );

        // =========================
        // SECURITY ALERTS
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

        // =========================
        // SEVERITY FILTER
        // =========================

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

        // =========================
        // ALERT TYPE FILTER
        // =========================

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

        // =========================
        // ALERT FILTER LOGIC
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
                        "ALL".equals(selectedSeverity)
                                || (
                                alert.getSeverity() != null
                                        && alert.getSeverity()
                                        .equalsIgnoreCase(
                                                selectedSeverity
                                        )
                        );

                boolean typeMatch =
                        "ALL".equals(selectedType)
                                || (
                                alert.getAlertType() != null
                                        && alert.getAlertType()
                                        .equalsIgnoreCase(
                                                selectedType
                                        )
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
        // SECURITY EVENTS
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
                                                || (
                                                securityEvent.getTimestamp() != null
                                                        && containsIgnoreCase(
                                                        securityEvent
                                                                .getTimestamp()
                                                                .toString(),
                                                        searchText
                                                )
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

        alertTypeChart =
                createAlertTypeChart();

        HBox charts =
                new HBox(
                        30,
                        eventTypeChart,
                        alertTypeChart
                );

        charts.setAlignment(
                Pos.CENTER
        );

        // =========================
        // MAIN LAYOUT
        // =========================

        VBox content =
                new VBox(
                        30,
                        header,
                        cards,
                        dataSourceControls,

                        alertsTitle,
                        alertFilters,
                        alertTable,

                        eventsTitle,
                        eventSearchField,
                        eventTable,

                        analyticsTitle,
                        charts
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

        // =========================
        // SCENE
        // =========================

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

        clockTimeline =
                new Timeline(
                        new KeyFrame(
                                Duration.seconds(1),
                                event ->
                                        updateClock()
                        )
                );

        clockTimeline.setCycleCount(
                Animation.INDEFINITE
        );

        clockTimeline.play();
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
    // PROCESS DEMO LOG FILE
    // =========================

    private void processLogs() {

        System.out.println(
                "Reading demo authentication log..."
        );

        List<String> logLines =
                logReader.readLogFile();

        for (String line : logLines) {

            SecurityEvent securityEvent =
                    logParser.parse(line);

            if (securityEvent != null) {

                databaseManager.saveEvent(
                        securityEvent
                );
            }
        }

        List<SecurityEvent> events =
                databaseManager.getAllEvents();

        List<SecurityAlert> detectedAlerts =
                detectionEngine.detect(
                        events
                );

        for (SecurityAlert alert : detectedAlerts) {

            if (alert != null) {

                databaseManager.saveAlert(
                        alert
                );
            }
        }

        System.out.println(
                "Demo log processing complete."
        );
    }

    // =========================
    // PROCESS WINDOWS EVENT LOG
    // =========================

    private void processWindowsEvents() {

        System.out.println(
                "Reading Windows Security Event Log..."
        );

        List<SecurityEvent> windowsEvents =
                windowsEventLogReader
                        .readSecurityEvents();

        System.out.println(
                "Windows events retrieved: "
                        + windowsEvents.size()
        );

        for (SecurityEvent securityEvent
                : windowsEvents) {

            if (securityEvent != null) {

                databaseManager.saveEvent(
                        securityEvent
                );
            }
        }

        // Reload events from SQLite
        List<SecurityEvent> allEvents =
                databaseManager.getAllEvents();

        // Run detection engine
        List<SecurityAlert> detectedAlerts =
                detectionEngine.detect(
                        allEvents
                );

        for (SecurityAlert alert
                : detectedAlerts) {

            if (alert != null) {

                databaseManager.saveAlert(
                        alert
                );
            }
        }

        System.out.println(
                "Windows Event Log processing complete."
        );
    }

    // =========================
    // REFRESH DASHBOARD
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
                                alert.getSeverity() != null
                                        && alert.getSeverity()
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
        updateAlertTypeChart();
    }

    // =========================
    // EVENT TYPE CHART
    // =========================

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
                480,
                350
        );

        return chart;
    }

    private void updateEventTypeChart() {

        Map<String, Long> eventCounts =
                new TreeMap<>();

        for (SecurityEvent event : eventData) {

            if (event.getEventType() == null) {
                continue;
            }

            String eventType =
                    event.getEventType();

            eventCounts.put(
                    eventType,
                    eventCounts.getOrDefault(
                            eventType,
                            0L
                    ) + 1
            );
        }

        ObservableList<PieChart.Data> chartData =
                FXCollections.observableArrayList();

        for (Map.Entry<String, Long> entry
                : eventCounts.entrySet()) {

            chartData.add(
                    new PieChart.Data(
                            entry.getKey()
                                    + " ("
                                    + entry.getValue()
                                    + ")",
                            entry.getValue()
                    )
            );
        }

        eventTypeChart.setData(
                chartData
        );
    }

    // =========================
    // ALERT TYPE CHART
    // =========================

    private PieChart createAlertTypeChart() {

        PieChart chart =
                new PieChart();

        chart.setTitle(
                "Alert Types"
        );

        chart.setLabelsVisible(
                true
        );

        chart.setLegendVisible(
                true
        );

        chart.setPrefSize(
                480,
                350
        );

        return chart;
    }

    private void updateAlertTypeChart() {

        Map<String, Long> alertCounts =
                new TreeMap<>();

        for (SecurityAlert alert : alertData) {

            if (alert.getAlertType() == null) {
                continue;
            }

            String alertType =
                    alert.getAlertType();

            alertCounts.put(
                    alertType,
                    alertCounts.getOrDefault(
                            alertType,
                            0L
                    ) + 1
            );
        }

        ObservableList<PieChart.Data> chartData =
                FXCollections.observableArrayList();

        for (Map.Entry<String, Long> entry
                : alertCounts.entrySet()) {

            chartData.add(
                    new PieChart.Data(
                            entry.getKey()
                                    + " ("
                                    + entry.getValue()
                                    + ")",
                            entry.getValue()
                    )
            );
        }

        alertTypeChart.setData(
                chartData
        );
    }

    // =========================
    // UTILITY
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