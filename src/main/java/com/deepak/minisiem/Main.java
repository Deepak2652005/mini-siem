package com.deepak.minisiem;

import com.deepak.minisiem.ui.DashboardApplication;
import javafx.application.Application;

public class Main {

    public static void main(String[] args) {

        System.out.println("================================");
        System.out.println("       MINI SIEM STARTING");
        System.out.println("================================");

        try {

            Application.launch(
                    DashboardApplication.class,
                    args
            );

        } catch (Exception exception) {

            System.err.println(
                    "Failed to start Mini SIEM Dashboard."
            );

            exception.printStackTrace();
        }
    }
}