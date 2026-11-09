
package com.security.analyzer;

import java.util.List;

public class LogReadResult {

    private List<LogEvent> events;
    private List<Integer> invalidLines;

    public LogReadResult(
            List<LogEvent> events,
            List<Integer> invalidLines) {

        this.events = events;
        this.invalidLines = invalidLines;
    }

    public List<LogEvent> getEvents() {
        return events;
    }

    public List<Integer> getInvalidLines() {
        return invalidLines;
    }

    public int getInvalidLineCount() {
        return invalidLines.size();
    }
}
