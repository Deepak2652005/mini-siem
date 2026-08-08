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
import javafx.concurrent.Task;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Scene;
import javafx.scene.chart.PieChart;
import javafx.scene.control.Alert;
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
import javafx.stage.FileChooser;
import javafx.stage.Stage;
import javafx.util.Duration;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;

public class DashboardApplication extends Application {

    // =========================
    // BACKEND
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
    // DATA
    // =========================

    private final ObservableList<SecurityAlert> alertData =
            FXCollections.observableArrayList();

    private final ObservableList<SecurityEvent> eventData =
            FXCollections.observableArrayList();

    // =========================
    // UI
    // =========================

    private Label totalEventsValue;
    private Label totalAlertsValue;
    private Label highSeverityValue;

    private Label clockLabel;
    private Label dateLabel;

    private Label monitoringStatusLabel;

    private PieChart eventTypeChart;
    private PieChart alertTypeChart;

    private ComboBox<String> dataSourceSelector;

    // =========================
    // TIMERS
    // =========================

    private Timeline clockTimeline;
    private Timeline windowsRefreshTimeline;

    private boolean windowsRefreshRunning =
            false;

    @Override
    public void start(Stage stage) {

        databaseManager.createTables();

        // =========================
        // HEADER
        // =========================

        Label title =
                new Label(
                        "MINI SIEM DASHBOARD"
                );

        title.getStyleClass().add(
                "dashboard-title"
        );

        clockLabel =
                new Label();

        dateLabel =
                new Label();

        clockLabel
                .getStyleClass()
                .add("clock-time");

        dateLabel
                .getStyleClass()
                .add("clock-date");

        VBox clockBox =
                new VBox(
                        3,
                        clockLabel,
                        dateLabel
                );

        clockBox.setAlignment(
                Pos.CENTER_RIGHT
        );

        Region spacer =
                new Region();

        HBox.setHgrow(
                spacer,
                Priority.ALWAYS
        );

        HBox header =
                new HBox(
                        20,
                        title,
                        spacer,
                        clockBox
                );

        header.setAlignment(
                Pos.CENTER_LEFT
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
                .add(
                        "high-severity-value"
                );

        HBox cards =
                new HBox(
                        20,
                        createCard(
                                "Total Events",
                                totalEventsValue
                        ),
                        createCard(
                                "Total Alerts",
                                totalAlertsValue
                        ),
                        createCard(
                                "High Severity",
                                highSeverityValue
                        )
                );

        cards.setAlignment(
                Pos.CENTER
        );

        // =========================
        // DATA SOURCE
        // =========================

        Label sourceLabel =
                new Label(
                        "Data Source:"
                );

        dataSourceSelector =
                new ComboBox<>();

        dataSourceSelector
                .getItems()
                .addAll(
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
                new Button(
                        "Refresh"
                );

        refreshButton.setPrefSize(
                120,
                38
        );

        // =========================
        // EXPORT BUTTONS
        // =========================

        Button exportAlertsButton =
                new Button(
                        "Export Alerts"
                );

        exportAlertsButton.setPrefSize(
                130,
                38
        );

        Button exportEventsButton =
                new Button(
                        "Export Events"
                );

        exportEventsButton.setPrefSize(
                130,
                38
        );

        exportAlertsButton.setOnAction(event ->
                exportAlertsToCsv(stage)
        );

        exportEventsButton.setOnAction(event ->
                exportEventsToCsv(stage)
        );

        // =========================
        // MONITORING STATUS
        // =========================

        monitoringStatusLabel =
                new Label();

        setStatusDemo();

        // =========================
        // REFRESH ACTION
        // =========================

        refreshButton.setOnAction(event -> {

            if ("Windows Event Log"
                    .equals(
                            dataSourceSelector
                                    .getValue()
                    )) {

                runWindowsRefreshInBackground();

            } else {

                processDemoLogs();

                refreshData();
            }
        });

        // =========================
        // SOURCE CHANGE
        // =========================

        dataSourceSelector.setOnAction(event -> {

            if ("Windows Event Log"
                    .equals(
                            dataSourceSelector
                                    .getValue()
                    )) {

                startWindowsAutoRefresh();

            } else {

                stopWindowsAutoRefresh();

                setStatusDemo();
            }
        });

        HBox sourceControls =
                new HBox(
                        15,
                        sourceLabel,
                        dataSourceSelector,
                        refreshButton,
                        exportAlertsButton,
                        exportEventsButton,
                        monitoringStatusLabel
                );

        sourceControls.setAlignment(
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

        TextField alertSearch =
                new TextField();

        alertSearch.setPromptText(
                "Search alert type, username, IP, message..."
        );

        alertSearch.setPrefWidth(
                400
        );

        ComboBox<String> severityFilter =
                new ComboBox<>();

        severityFilter
                .getItems()
                .addAll(
                        "ALL",
                        "HIGH",
                        "MEDIUM",
                        "LOW"
                );

        severityFilter.setValue(
                "ALL"
        );

        severityFilter.setPrefWidth(
                120
        );

        ComboBox<String> typeFilter =
                new ComboBox<>();

        typeFilter
                .getItems()
                .addAll(
                        "ALL",
                        "BRUTE_FORCE",
                        "PASSWORD_SPRAY",
                        "SUSPICIOUS_POWERSHELL",
                        "SUSPICIOUS_COMMAND",
                        "SCRIPT_EXECUTION",
                        "LOLBIN_EXECUTION"
                );

        typeFilter.setValue(
                "ALL"
        );

        typeFilter.setPrefWidth(
                220
        );

        // =========================
        // ALERT FILTER LOGIC
        // =========================

        Runnable updateAlertFilter = () -> {

            String search =
                    alertSearch
                            .getText()
                            .trim()
                            .toLowerCase();

            String severity =
                    severityFilter
                            .getValue();

            String type =
                    typeFilter
                            .getValue();

            filteredAlerts.setPredicate(alert -> {

                boolean searchMatch =
                        search.isEmpty()
                                || containsIgnoreCase(
                                alert.getAlertType(),
                                search
                        )
                                || containsIgnoreCase(
                                alert.getSeverity(),
                                search
                        )
                                || containsIgnoreCase(
                                alert.getUsername(),
                                search
                        )
                                || containsIgnoreCase(
                                alert.getIpAddress(),
                                search
                        )
                                || containsIgnoreCase(
                                alert.getMessage(),
                                search
                        );

                boolean severityMatch =
                        "ALL".equals(severity)
                                || (
                                alert.getSeverity()
                                        != null
                                        && alert
                                        .getSeverity()
                                        .equalsIgnoreCase(
                                                severity
                                        )
                        );

                boolean typeMatch =
                        "ALL".equals(type)
                                || (
                                alert.getAlertType()
                                        != null
                                        && alert
                                        .getAlertType()
                                        .equalsIgnoreCase(
                                                type
                                        )
                        );

                return searchMatch
                        && severityMatch
                        && typeMatch;
            });
        };

        alertSearch
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
                        alertSearch,
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
        // DOUBLE CLICK ALERT DETAILS
        // =========================

        alertTable.setOnMouseClicked(event -> {

            if (event.getClickCount() == 2) {

                SecurityAlert selectedAlert =
                        alertTable
                                .getSelectionModel()
                                .getSelectedItem();

                if (selectedAlert != null) {

                    showAlertDetails(
                            selectedAlert
                    );
                }
            }
        });

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
                        event -> true
                );

        TextField eventSearch =
                new TextField();

        eventSearch.setPromptText(
                "Search event type, username, process, command line..."
        );

        eventSearch.setMaxWidth(
                650
        );

        eventSearch
                .textProperty()
                .addListener(
                        (observable, oldValue, value) -> {

                            String search =
                                    value
                                            .trim()
                                            .toLowerCase();

                            filteredEvents.setPredicate(
                                    securityEvent -> {

                                        if (search.isEmpty()) {
                                            return true;
                                        }

                                        return containsIgnoreCase(
                                                securityEvent
                                                        .getUsername(),
                                                search
                                        )
                                                || containsIgnoreCase(
                                                securityEvent
                                                        .getIpAddress(),
                                                search
                                        )
                                                || containsIgnoreCase(
                                                securityEvent
                                                        .getEventType(),
                                                search
                                        )
                                                || containsIgnoreCase(
                                                securityEvent
                                                        .getDetails(),
                                                search
                                        )
                                                || containsIgnoreCase(
                                                securityEvent
                                                        .getCommandLine(),
                                                search
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
                        sourceControls,

                        alertsTitle,
                        alertFilters,
                        alertTable,

                        eventsTitle,
                        eventSearch,
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

        Scene scene =
                new Scene(
                        scrollPane,
                        1400,
                        850
                );

        scene
                .getStylesheets()
                .add(
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

        stage.setOnCloseRequest(event -> {

            stopWindowsAutoRefresh();

            if (clockTimeline != null) {

                clockTimeline.stop();
            }
        });

        refreshData();
    }

    // =========================
    // CLOCK
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

        clockLabel.setText(
                now.format(
                        DateTimeFormatter
                                .ofPattern(
                                        "hh:mm:ss a"
                                )
                )
        );

        dateLabel.setText(
                now.format(
                        DateTimeFormatter
                                .ofPattern(
                                        "dd MMM yyyy"
                                )
                )
        );
    }

    // =========================
    // DEMO LOG
    // =========================

    private void processDemoLogs() {

        List<String> lines =
                logReader.readLogFile();

        for (String line : lines) {

            SecurityEvent event =
                    logParser.parse(
                            line
                    );

            if (event != null) {

                databaseManager.saveEvent(
                        event
                );
            }
        }

        runDetectionEngine();
    }

    // =========================
    // WINDOWS EVENTS
    // =========================

    private void processWindowsEvents() {

        long lastRecordId =
                databaseManager
                        .getLatestSourceEventId();

        System.out.println(
                "Checking for new Windows events..."
        );

        List<SecurityEvent> windowsEvents =
                windowsEventLogReader
                        .readSecurityEventsAfter(
                                lastRecordId
                        );

        if (windowsEvents.isEmpty()) {



            return;
        }

        for (SecurityEvent event
                : windowsEvents) {

            if (event != null) {

                databaseManager.saveEvent(
                        event
                );
            }
        }

        System.out.println(
                "New Windows events saved: "
                        + windowsEvents.size()
        );

        runDetectionEngine();
    }

    // =========================
    // DETECTION
    // =========================

    private void runDetectionEngine() {

        List<SecurityAlert> alerts =
                detectionEngine.detect(
                        databaseManager
                                .getAllEvents()
                );

        for (SecurityAlert alert : alerts) {

            if (alert != null) {

                databaseManager.saveAlert(
                        alert
                );
            }
        }
    }

    // =========================
    // LIVE MONITORING
    // =========================

    private void startWindowsAutoRefresh() {

        stopWindowsAutoRefresh();

        setStatusLive();

        runWindowsRefreshInBackground();

        windowsRefreshTimeline =
                new Timeline(
                        new KeyFrame(
                                Duration.seconds(5),
                                event ->
                                        runWindowsRefreshInBackground()
                        )
                );

        windowsRefreshTimeline.setCycleCount(
                Animation.INDEFINITE
        );

        windowsRefreshTimeline.play();

        System.out.println(
                "Windows LIVE monitoring started."
        );
    }

    private void stopWindowsAutoRefresh() {

        if (windowsRefreshTimeline != null) {

            windowsRefreshTimeline.stop();

            windowsRefreshTimeline =
                    null;
        }
    }

    // =========================
    // WINDOWS BACKGROUND TASK
    // =========================

    private void runWindowsRefreshInBackground() {

        if (windowsRefreshRunning) {
            return;
        }

        windowsRefreshRunning =
                true;

        setStatusScanning();

        Task<Void> task =
                new Task<>() {

                    @Override
                    protected Void call() {

                        processWindowsEvents();

                        return null;
                    }
                };

        task.setOnSucceeded(event -> {

            windowsRefreshRunning =
                    false;

            refreshData();

            if ("Windows Event Log"
                    .equals(
                            dataSourceSelector
                                    .getValue()
                    )) {

                setStatusLive();
            }
        });

        task.setOnFailed(event -> {

            windowsRefreshRunning =
                    false;

            setStatusError();

            if (task.getException() != null) {

                task.getException()
                        .printStackTrace();
            }
        });

        Thread thread =
                new Thread(
                        task
                );

        thread.setDaemon(
                true
        );

        thread.start();
    }

    // =========================
    // STATUS
    // =========================

    private void setStatusDemo() {

        monitoringStatusLabel.setText(
                "DEMO MODE"
        );

        monitoringStatusLabel.setStyle(
                "-fx-text-fill:#94a3b8;"
                        + "-fx-font-weight:bold;"
        );
    }

    private void setStatusLive() {

        monitoringStatusLabel.setText(
                "LIVE"
        );

        monitoringStatusLabel.setStyle(
                "-fx-text-fill:#22c55e;"
                        + "-fx-font-weight:bold;"
        );
    }

    private void setStatusScanning() {

        monitoringStatusLabel.setText(
                "SCANNING..."
        );

        monitoringStatusLabel.setStyle(
                "-fx-text-fill:#38bdf8;"
                        + "-fx-font-weight:bold;"
        );
    }

    private void setStatusError() {

        monitoringStatusLabel.setText(
                "ERROR"
        );

        monitoringStatusLabel.setStyle(
                "-fx-text-fill:#ef4444;"
                        + "-fx-font-weight:bold;"
        );
    }

    // =========================
    // REFRESH DASHBOARD
    // =========================

    private void refreshData() {

        alertData.setAll(
                databaseManager
                        .getAllAlerts()
        );

        eventData.setAll(
                databaseManager
                        .getAllEvents()
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

        long highCount =
                alertData.stream()
                        .filter(alert ->
                                "HIGH"
                                        .equalsIgnoreCase(
                                                alert.getSeverity()
                                        )
                        )
                        .count();

        highSeverityValue.setText(
                String.valueOf(
                        highCount
                )
        );

        updateEventTypeChart();

        updateAlertTypeChart();
    }

    // =========================
    // EVENT CHART
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
                520,
                380
        );

        return chart;
    }

    private void updateEventTypeChart() {

        Map<String, Long> counts =
                new TreeMap<>();

        for (SecurityEvent event : eventData) {

            if (event.getEventType() == null) {
                continue;
            }

            counts.put(
                    event.getEventType(),
                    counts.getOrDefault(
                            event.getEventType(),
                            0L
                    ) + 1
            );
        }

        ObservableList<PieChart.Data> data =
                FXCollections
                        .observableArrayList();

        counts.forEach(
                (name, count) ->
                        data.add(
                                new PieChart.Data(
                                        name
                                                + " ("
                                                + count
                                                + ")",
                                        count
                                )
                        )
        );

        eventTypeChart.setData(
                data
        );
    }

    // =========================
    // ALERT CHART
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
                520,
                380
        );

        return chart;
    }

    private void updateAlertTypeChart() {

        Map<String, Long> counts =
                new TreeMap<>();

        for (SecurityAlert alert : alertData) {

            if (alert.getAlertType() == null) {
                continue;
            }

            counts.put(
                    alert.getAlertType(),
                    counts.getOrDefault(
                            alert.getAlertType(),
                            0L
                    ) + 1
            );
        }

        ObservableList<PieChart.Data> data =
                FXCollections
                        .observableArrayList();

        counts.forEach(
                (name, count) ->
                        data.add(
                                new PieChart.Data(
                                        name
                                                + " ("
                                                + count
                                                + ")",
                                        count
                                )
                        )
        );

        alertTypeChart.setData(
                data
        );
    }

    // =========================
    // EXPORT ALERTS
    // =========================

    private void exportAlertsToCsv(
            Stage stage) {

        FileChooser fileChooser =
                new FileChooser();

        fileChooser.setTitle(
                "Export Security Alerts"
        );

        fileChooser.setInitialFileName(
                "mini-siem-alerts.csv"
        );

        fileChooser
                .getExtensionFilters()
                .add(
                        new FileChooser.ExtensionFilter(
                                "CSV Files",
                                "*.csv"
                        )
                );

        File file =
                fileChooser.showSaveDialog(
                        stage
                );

        if (file == null) {
            return;
        }

        try (BufferedWriter writer =
                     new BufferedWriter(
                             new FileWriter(
                                     file
                             )
                     )) {

            writer.write(
                    "Type,Severity,Username,IP Address,Message"
            );

            writer.newLine();

            for (SecurityAlert alert : alertData) {

                writer.write(
                        escapeCsv(
                                alert.getAlertType()
                        )
                                + ","
                                + escapeCsv(
                                alert.getSeverity()
                        )
                                + ","
                                + escapeCsv(
                                alert.getUsername()
                        )
                                + ","
                                + escapeCsv(
                                alert.getIpAddress()
                        )
                                + ","
                                + escapeCsv(
                                alert.getMessage()
                        )
                );

                writer.newLine();
            }

            showExportSuccess(
                    "Alerts exported successfully.",
                    file
            );

        } catch (IOException exception) {

            showExportError(
                    exception
            );
        }
    }

    // =========================
    // EXPORT EVENTS
    // =========================

    private void exportEventsToCsv(
            Stage stage) {

        FileChooser fileChooser =
                new FileChooser();

        fileChooser.setTitle(
                "Export Security Events"
        );

        fileChooser.setInitialFileName(
                "mini-siem-events.csv"
        );

        fileChooser
                .getExtensionFilters()
                .add(
                        new FileChooser.ExtensionFilter(
                                "CSV Files",
                                "*.csv"
                        )
                );

        File file =
                fileChooser.showSaveDialog(
                        stage
                );

        if (file == null) {
            return;
        }

        try (BufferedWriter writer =
                     new BufferedWriter(
                             new FileWriter(
                                     file
                             )
                     )) {

            writer.write(
                    "Timestamp,Event Type,Username,IP Address,Process,Command Line"
            );

            writer.newLine();

            for (SecurityEvent event : eventData) {

                writer.write(
                        escapeCsv(
                                event.getTimestamp() != null
                                        ? event.getTimestamp()
                                        .toString()
                                        : ""
                        )
                                + ","
                                + escapeCsv(
                                event.getEventType()
                        )
                                + ","
                                + escapeCsv(
                                event.getUsername()
                        )
                                + ","
                                + escapeCsv(
                                event.getIpAddress()
                        )
                                + ","
                                + escapeCsv(
                                event.getDetails()
                        )
                                + ","
                                + escapeCsv(
                                event.getCommandLine()
                        )
                );

                writer.newLine();
            }

            showExportSuccess(
                    "Events exported successfully.",
                    file
            );

        } catch (IOException exception) {

            showExportError(
                    exception
            );
        }
    }

    // =========================
    // CSV ESCAPE
    // =========================

    private String escapeCsv(
            String value) {

        if (value == null) {
            return "";
        }

        String escaped =
                value.replace(
                        "\"",
                        "\"\""
                );

        return "\""
                + escaped
                + "\"";
    }

    // =========================
    // EXPORT SUCCESS
    // =========================

    private void showExportSuccess(
            String message,
            File file) {

        Alert alert =
                new Alert(
                        Alert.AlertType.INFORMATION
                );

        alert.setTitle(
                "Export Complete"
        );

        alert.setHeaderText(
                message
        );

        alert.setContentText(
                "Saved to:\n"
                        + file.getAbsolutePath()
        );

        alert.showAndWait();
    }

    // =========================
    // EXPORT ERROR
    // =========================

    private void showExportError(
            Exception exception) {

        Alert alert =
                new Alert(
                        Alert.AlertType.ERROR
                );

        alert.setTitle(
                "Export Failed"
        );

        alert.setHeaderText(
                "Could not export CSV file."
        );

        alert.setContentText(
                exception.getMessage()
        );

        alert.showAndWait();
    }

    // =========================
    // UTILITIES
    // =========================

    private boolean containsIgnoreCase(
            String value,
            String search) {

        return value != null
                && value
                .toLowerCase()
                .contains(
                        search
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

    private TableView<SecurityAlert>
    createAlertTable(
            ObservableList<SecurityAlert> alerts) {

        TableView<SecurityAlert> table =
                new TableView<>();

        TableColumn<SecurityAlert, String> type =
                new TableColumn<>(
                        "Type"
                );

        type.setCellValueFactory(
                new PropertyValueFactory<>(
                        "alertType"
                )
        );

        TableColumn<SecurityAlert, String> severity =
                new TableColumn<>(
                        "Severity"
                );

        severity.setCellValueFactory(
                new PropertyValueFactory<>(
                        "severity"
                )
        );

        severity.setCellFactory(
                column ->
                        new TableCell<>() {

                            @Override
                            protected void updateItem(
                                    String value,
                                    boolean empty) {

                                super.updateItem(
                                        value,
                                        empty
                                );

                                if (empty
                                        || value == null) {

                                    setText(null);

                                    setStyle("");

                                    return;
                                }

                                setText(
                                        value
                                );

                                switch (
                                        value.toUpperCase()
                                ) {

                                    case "HIGH" ->
                                            setStyle(
                                                    "-fx-text-fill:#ef4444;"
                                                            + "-fx-font-weight:bold;"
                                            );

                                    case "MEDIUM" ->
                                            setStyle(
                                                    "-fx-text-fill:#f59e0b;"
                                                            + "-fx-font-weight:bold;"
                                            );

                                    case "LOW" ->
                                            setStyle(
                                                    "-fx-text-fill:#22c55e;"
                                                            + "-fx-font-weight:bold;"
                                            );

                                    default ->
                                            setStyle("");
                                }
                            }
                        }
        );

        TableColumn<SecurityAlert, String> username =
                new TableColumn<>(
                        "Username"
                );

        username.setCellValueFactory(
                new PropertyValueFactory<>(
                        "username"
                )
        );

        TableColumn<SecurityAlert, String> ip =
                new TableColumn<>(
                        "IP Address"
                );

        ip.setCellValueFactory(
                new PropertyValueFactory<>(
                        "ipAddress"
                )
        );

        TableColumn<SecurityAlert, String> message =
                new TableColumn<>(
                        "Message"
                );

        message.setCellValueFactory(
                new PropertyValueFactory<>(
                        "message"
                )
        );

        table.getColumns().addAll(
                type,
                severity,
                username,
                ip,
                message
        );

        table.setItems(
                alerts
        );

        table.setColumnResizePolicy(
                TableView
                        .CONSTRAINED_RESIZE_POLICY_FLEX_LAST_COLUMN
        );

        table.setPrefHeight(
                250
        );

        return table;
    }

    // =========================
    // EVENT TABLE
    // =========================

    private TableView<SecurityEvent>
    createEventTable(
            ObservableList<SecurityEvent> events) {

        TableView<SecurityEvent> table =
                new TableView<>();

        TableColumn<SecurityEvent, LocalDateTime> timestamp =
                new TableColumn<>(
                        "Timestamp"
                );

        timestamp.setCellValueFactory(
                new PropertyValueFactory<>(
                        "timestamp"
                )
        );

        timestamp.setPrefWidth(
                180
        );

        TableColumn<SecurityEvent, String> type =
                new TableColumn<>(
                        "Event Type"
                );

        type.setCellValueFactory(
                new PropertyValueFactory<>(
                        "eventType"
                )
        );

        type.setPrefWidth(
                170
        );

        TableColumn<SecurityEvent, String> username =
                new TableColumn<>(
                        "Username"
                );

        username.setCellValueFactory(
                new PropertyValueFactory<>(
                        "username"
                )
        );

        username.setPrefWidth(
                140
        );

        TableColumn<SecurityEvent, String> ip =
                new TableColumn<>(
                        "IP Address"
                );

        ip.setCellValueFactory(
                new PropertyValueFactory<>(
                        "ipAddress"
                )
        );

        ip.setPrefWidth(
                130
        );

        TableColumn<SecurityEvent, String> process =
                new TableColumn<>(
                        "Process"
                );

        process.setCellValueFactory(
                new PropertyValueFactory<>(
                        "details"
                )
        );

        process.setPrefWidth(
                350
        );

        TableColumn<SecurityEvent, String> commandLine =
                new TableColumn<>(
                        "Command Line"
                );

        commandLine.setCellValueFactory(
                new PropertyValueFactory<>(
                        "commandLine"
                )
        );

        commandLine.setPrefWidth(
                500
        );

        table.getColumns().addAll(
                timestamp,
                type,
                username,
                ip,
                process,
                commandLine
        );

        table.setItems(
                events
        );

        table.setPrefHeight(
                400
        );

        return table;
    }

    // =========================
    // ALERT DETAILS POPUP
    // =========================

    private void showAlertDetails(
            SecurityAlert alert) {

        Alert dialog =
                new Alert(
                        Alert.AlertType.INFORMATION
                );

        dialog.setTitle(
                "Security Alert Details"
        );

        dialog.setHeaderText(
                alert.getAlertType()
                        + " - "
                        + alert.getSeverity()
        );

        String content =
                "Type: "
                        + alert.getAlertType()
                        + "\n\n"

                        + "Severity: "
                        + alert.getSeverity()
                        + "\n\n"

                        + "Username: "
                        + alert.getUsername()
                        + "\n\n"

                        + "IP Address: "
                        + alert.getIpAddress()
                        + "\n\n"

                        + "Message:\n"
                        + alert.getMessage();

        dialog.setContentText(
                content
        );

        dialog.getDialogPane()
                .setPrefWidth(
                        700
                );

        dialog.setResizable(
                true
        );

        dialog.showAndWait();
    }

    // =========================
    // SUMMARY CARD
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