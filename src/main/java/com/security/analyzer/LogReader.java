
package com.security.analyzer;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class LogReader {

  private static final Pattern LOG_PATTERN = Pattern.compile(
    "^(\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2})\\s+(LOGIN_SUCCESS|LOGIN_FAILED|LOGOUT)\\s+user=(\\S+)$"
);
    

    private static final DateTimeFormatter FORMATTER =
        DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    public static LogReadResult readLogs(Path filePath)
            throws IOException {

        List<String> lines = Files.readAllLines(filePath);

        List<LogEvent> events = new ArrayList<>();
        List<Integer> invalidLines = new ArrayList<>();

        int lineNumber = 0;

        for (String line : lines) {

            lineNumber++;

            Matcher matcher = LOG_PATTERN.matcher(line);

            if (matcher.matches()) {

                String timestamp = matcher.group(1);
                String eventType = matcher.group(2);
                String username = matcher.group(3);

                try {
                    // Validate the timestamp
                    LocalDateTime.parse(timestamp, FORMATTER);

                    events.add(new LogEvent(
                        timestamp,
                        eventType,
                        username
                    ));

                } catch (DateTimeParseException e) {
                    invalidLines.add(lineNumber);
                }

            } else {
                invalidLines.add(lineNumber);
            }
        }

        return new LogReadResult(events, invalidLines);
    }
}
