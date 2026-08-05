package com.deepak.minisiem;

import com.deepak.minisiem.reader.LogReader;

public class Main {

    public static void main(String[] args) {

        System.out.println("===== MINI SIEM =====");

        LogReader logReader = new LogReader();

        logReader.readLogFile();

    }

}