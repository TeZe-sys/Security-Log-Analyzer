
package com.security.analyzer;

public class SecurityAlert {

    private String username;
    private String description;
    private int attempts;
    private String detectedAt;

    public SecurityAlert(
            String username,
            String description,
            int attempts,
            String detectedAt) {

        this.username = username;
        this.description = description;
        this.attempts = attempts;
        this.detectedAt = detectedAt;
    }

    public String getUsername() {
        return username;
    }

    public String getDescription() {
        return description;
    }

    public int getAttempts() {
        return attempts;
    }

    public String getDetectedAt() {
        return detectedAt;
    }
}
