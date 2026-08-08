package com.deepak.minisiem.ui;

import com.deepak.minisiem.alert.SecurityAlert;
import com.deepak.minisiem.database.DatabaseManager;

import javafx.application.Application;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Scene;
import javafx.scene.control.Label;
import javafx.scene.control.TableColumn;
import javafx.scene.control.TableView;
import javafx.scene.control.cell.PropertyValueFactory;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.VBox;
import javafx.stage.Stage;

import java.util.List;

public class DashboardApplication extends Application {

    @Override
    public void start(Stage stage) {

        DatabaseManager databaseManager = new DatabaseManager();

        // Get data from SQLite
        int totalEvents =
                databaseManager.getEventCount();

        int totalAlerts =
                databaseManager.getAlertCount();

        List<SecurityAlert> alerts =
                databaseManager.getAllAlerts();

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
        // Alerts section title
        // =========================

        Label alertsTitle =
                new Label("SECURITY ALERTS");

        alertsTitle.setStyle(
                "-fx-font-size: 20px;" +
                        "-fx-font-weight: bold;"
        );

        // =========================
        // Alerts table
        // =========================

        TableView<SecurityAlert> alertTable =
                new TableView<>();

        // Alert Type column
        TableColumn<SecurityAlert, String> typeColumn =
                new TableColumn<>("Type");

        typeColumn.setCellValueFactory(
                new PropertyValueFactory<>("alertType")
        );

        // Severity column
        TableColumn<SecurityAlert, String> severityColumn =
                new TableColumn<>("Severity");

        severityColumn.setCellValueFactory(
                new PropertyValueFactory<>("severity")
        );

        // Username column
        TableColumn<SecurityAlert, String> usernameColumn =
                new TableColumn<>("Username");

        usernameColumn.setCellValueFactory(
                new PropertyValueFactory<>("username")
        );

        // IP Address column
        TableColumn<SecurityAlert, String> ipColumn =
                new TableColumn<>("IP Address");

        ipColumn.setCellValueFactory(
                new PropertyValueFactory<>("ipAddress")
        );

        // Message column
        TableColumn<SecurityAlert, String> messageColumn =
                new TableColumn<>("Message");

        messageColumn.setCellValueFactory(
                new PropertyValueFactory<>("message")
        );

        // Add columns to table
        alertTable.getColumns().addAll(
                typeColumn,
                severityColumn,
                usernameColumn,
                ipColumn,
                messageColumn
        );

        // Convert database List into JavaFX ObservableList
        ObservableList<SecurityAlert> alertData =
                FXCollections.observableArrayList(alerts);

        alertTable.setItems(alertData);

        // Resize columns automatically
        alertTable.setColumnResizePolicy(
                TableView.CONSTRAINED_RESIZE_POLICY_FLEX_LAST_COLUMN
        );

        alertTable.setPrefHeight(300);

        // =========================
        // Main layout
        // =========================

        VBox root = new VBox(
                30,
                title,
                cards,
                alertsTitle,
                alertTable
        );

        root.setPadding(new Insets(40));

        root.setAlignment(Pos.TOP_CENTER);

        VBox.setVgrow(
                alertTable,
                Priority.ALWAYS
        );

        // =========================
        // Scene
        // =========================

        Scene scene =
                new Scene(root, 1100, 700);

        stage.setTitle("Mini SIEM Dashboard");

        stage.setScene(scene);

        stage.show();
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

        VBox card =
                new VBox(
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