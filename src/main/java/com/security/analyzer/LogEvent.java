
package com.security.analyzer;

public class LogEvent {

    private String timestamp;
    private String eventType;
    private String username;

    public LogEvent(String timestamp, String eventType, String username) {
        this.timestamp = timestamp;
        this.eventType = eventType;
        this.username = username;
    }

    public String getTimestamp() {
        return timestamp;
    }

    public String getEventType() {
        return eventType;
    }

    public String getUsername() {
        return username;
    }
}
