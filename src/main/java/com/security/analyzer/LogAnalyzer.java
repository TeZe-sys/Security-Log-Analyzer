
package com.security.analyzer;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class LogAnalyzer {

    private static final int MAX_ATTEMPTS = 3;
    private static final int TIME_WINDOW_MINUTES = 5;

    private static final DateTimeFormatter FORMATTER =
        DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    public static List<SecurityAlert> analyze(List<LogEvent> events) {

        List<SecurityAlert> alerts = new ArrayList<>();

        // Create a sorted copy without modifying the original list
        List<LogEvent> sortedEvents = new ArrayList<>(events);

        sortedEvents.sort(Comparator.comparing(
            event -> LocalDateTime.parse(event.getTimestamp(), FORMATTER)
        ));

        Map<String, List<LocalDateTime>> failedAttempts =
            new HashMap<>();

        for (LogEvent event : sortedEvents) {

            String username = event.getUsername();

            LocalDateTime timestamp =
                LocalDateTime.parse(event.getTimestamp(), FORMATTER);

            List<LocalDateTime> attempts =
                failedAttempts.computeIfAbsent(
                    username, key -> new ArrayList<>()
                );

            // Remove attempts outside the five-minute window
            attempts.removeIf(time ->
                time.isBefore(timestamp.minusMinutes(TIME_WINDOW_MINUTES))
            );

            // Check for successful login after repeated failures
            if (event.getEventType().equals("LOGIN_SUCCESS")) {

                if (attempts.size() >= MAX_ATTEMPTS) {

                    alerts.add(new SecurityAlert(
                        username,
                        "Successful login after repeated failed attempts",
                        attempts.size(),
                        timestamp.toString()
                    ));
                }

                attempts.clear();
                continue;
            }

            if (!event.getEventType().equals("LOGIN_FAILED")) {
                continue;
            }

            attempts.add(timestamp);

            // Detect possible brute-force activity
            if (attempts.size() == MAX_ATTEMPTS) {

                alerts.add(new SecurityAlert(
                    username,
                    "Possible brute-force login attack",
                    attempts.size(),
                    timestamp.toString()
                ));
            }
        }

        return alerts;
    }
}
