package com.deepak.minisiem.ui;

import javafx.application.Application;
import javafx.scene.Scene;
import javafx.scene.control.Label;
import javafx.scene.layout.StackPane;
import javafx.stage.Stage;

public class DashboardApplication extends Application {

    @Override
    public void start(Stage stage) {

        Label title = new Label("MINI SIEM DASHBOARD");

        StackPane root = new StackPane(title);

        Scene scene = new Scene(root, 900, 600);

        stage.setTitle("Mini SIEM");
        stage.setScene(scene);
        stage.show();
    }
}