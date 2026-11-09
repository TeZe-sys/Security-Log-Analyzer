
package com.security.analyzer;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.util.List;

public class ReportGenerator {

    public static void generateReport(
            List<LogEvent> events,
            List<SecurityAlert> alerts,
            LogReadResult readResult,
            Path outputPath) throws IOException {

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

        StringBuilder report = new StringBuilder();

        report.append("====================================\n");
        report.append("       SECURITY ANALYSIS REPORT     \n");
        report.append("====================================\n\n");

        report.append("Generated at: ")
              .append(LocalDateTime.now())
              .append("\n\n");

        // Event summary
        report.append("========== EVENT SUMMARY ==========\n");
        report.append("Total valid events: ")
              .append(events.size()).append("\n");

        report.append("Successful logins: ")
              .append(successfulLogins).append("\n");

        report.append("Failed logins: ")
              .append(failedLogins).append("\n");

        report.append("Logouts: ")
              .append(logouts).append("\n\n");

        // Log validation summary
        report.append("========== LOG VALIDATION ==========\n");

        report.append("Invalid log lines: ")
              .append(readResult.getInvalidLineCount())
              .append("\n");

        if (readResult.getInvalidLines().isEmpty()) {

            report.append("All log entries are valid.\n");

        } else {

            report.append("Invalid line numbers: ")
                  .append(readResult.getInvalidLines())
                  .append("\n");
        }

        // Security alerts
        report.append("\n========== SECURITY ALERTS ==========\n");

        if (alerts.isEmpty()) {

            report.append("No suspicious activity detected.\n");

        } else {

            for (SecurityAlert alert : alerts) {

                report.append("WARNING: ")
                      .append(alert.getDescription())
                      .append("\n");

                report.append("Username: ")
                      .append(alert.getUsername())
                      .append("\n");

                report.append("Failed attempts: ")
                      .append(alert.getAttempts())
                      .append("\n");

                report.append("Detected at: ")
                      .append(alert.getDetectedAt())
                      .append("\n");

                report.append("------------------------------------\n");
            }
        }

        report.append("\n========== END OF REPORT ==========\n");

        Path parent = outputPath.getParent();

        if (parent != null) {
            Files.createDirectories(parent);
        }

        Files.writeString(outputPath, report.toString());

        System.out.println("Security report saved to: " + outputPath);
    }
}
