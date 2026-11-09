
package com.security.analyzer;

import java.io.IOException;
import java.nio.file.Path;
import java.util.List;

public class App {

    public static void main(String[] args) {

        Path logFile = args.length >= 1
                ? Path.of(args[0])
                : Path.of("logs", "sample.log");

        Path reportFile = args.length >= 2
                ? Path.of(args[1])
                : Path.of("reports", "security-report.txt");

        // Read input log file
        LogReadResult readResult;

        try {

            readResult = LogReader.readLogs(logFile);

        } catch (IOException e) {

            System.out.println(
                    "ERROR: Unable to read the input log file."
            );
            System.out.println("Reason: " + e.getMessage());
            System.out.println(
                    "Please check the file path and permissions."
            );

            return;
        }

        List<LogEvent> events = readResult.getEvents();

        // Count login events
        int successfulLogins = 0;
        int failedLogins = 0;
        int logouts = 0;

        for (LogEvent event : events) {

            switch (event.getEventType()) {

                case "LOGIN_SUCCESS":
                    successfulLogins++;
                    break;

                case "LOGIN_FAILED":
                    failedLogins++;
                    break;

                case "LOGOUT":
                    logouts++;
                    break;
            }
        }

        // Analyze logs
        List<SecurityAlert> alerts =
                LogAnalyzer.analyze(events);

        // Display analysis
        System.out.println("===== SECURITY ANALYSIS =====");
        System.out.println("Total valid events: " + events.size());
        System.out.println("Successful logins: " + successfulLogins);
        System.out.println("Failed logins: " + failedLogins);
        System.out.println("Logouts: " + logouts);

        // Display validation information
        System.out.println("\n===== LOG VALIDATION =====");

        System.out.println("Invalid log lines: "
                + readResult.getInvalidLineCount());

        if (events.isEmpty()
                && readResult.getInvalidLineCount() == 0) {

            System.out.println(
                    "Input log file is empty; nothing to analyze."
            );

        } else if (!readResult.getInvalidLines().isEmpty()) {

            System.out.println("Invalid line numbers: "
                    + readResult.getInvalidLines());

        } else {

            System.out.println("All log entries are valid.");
        }

        // Display security alerts
        System.out.println("\n===== SECURITY ALERTS =====");

        if (events.isEmpty()) {

            System.out.println("No events available to analyze.");

        } else if (alerts.isEmpty()) {

            System.out.println("No suspicious activity detected.");

        } else {

            for (SecurityAlert alert : alerts) {

                System.out.println("WARNING: "
                        + alert.getDescription());

                System.out.println("Username: "
                        + alert.getUsername());

                System.out.println("Failed attempts: "
                        + alert.getAttempts());

                System.out.println("Detected at: "
                        + alert.getDetectedAt());

                System.out.println("---------------------------");
            }
        }

        // Generate report separately
        try {

            ReportGenerator.generateReport(
                    events,
                    alerts,
                    readResult,
                    reportFile
            );

        } catch (IOException e) {

            System.out.println(
                    "ERROR: Unable to generate the security report."
            );
            System.out.println("Reason: " + e.getMessage());
            System.out.println(
                    "Please check the output path and permissions."
            );
        }
    }
}
