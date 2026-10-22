
package com.deepak.minisiem;

import com.deepak.minisiem.ui.DashboardApplication;
import javafx.application.Application;

public final class Main {

    private Main() {
        // Prevent instantiation of the application entry-point class.
    }

    public static void main(String[] args) {
        System.out.println("================================");
        System.out.println("       MINI SIEM STARTING");
        System.out.println("================================");

        try {
            Application.launch(DashboardApplication.class, args);
        } catch (Exception exception) {
            System.err.println(
                    "Failed to start Mini SIEM Dashboard: "
                            + exception.getMessage()
            );
            exception.printStackTrace();
            System.exit(1);
        }
    }
}
