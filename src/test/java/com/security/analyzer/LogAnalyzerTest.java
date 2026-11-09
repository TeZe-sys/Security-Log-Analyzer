
package com.security.analyzer;

import java.util.Arrays;
import java.util.List;

import static org.junit.Assert.assertEquals;
import org.junit.Test;

public class LogAnalyzerTest {

    @Test
    public void shouldDetectBruteForceAttack() {

        List<LogEvent> events = Arrays.asList(
            new LogEvent("2026-11-08 10:00:00", "LOGIN_FAILED", "admin"),
            new LogEvent("2026-11-08 10:02:00", "LOGIN_FAILED", "admin"),
            new LogEvent("2026-11-08 10:04:00", "LOGIN_FAILED", "admin")
        );

        List<SecurityAlert> alerts = LogAnalyzer.analyze(events);

        assertEquals(1, alerts.size());
        assertEquals("admin", alerts.get(0).getUsername());
        assertEquals(3, alerts.get(0).getAttempts());
    }

    @Test
    public void shouldNotDetectBruteForceWithOnlyTwoAttempts() {

        List<LogEvent> events = Arrays.asList(
            new LogEvent("2026-11-08 10:00:00", "LOGIN_FAILED", "guest"),
            new LogEvent("2026-11-08 10:02:00", "LOGIN_FAILED", "guest")
        );

        List<SecurityAlert> alerts = LogAnalyzer.analyze(events);

        assertEquals(0, alerts.size());
    }

    @Test
    public void shouldNotDetectAttemptsOutsideFiveMinuteWindow() {

        List<LogEvent> events = Arrays.asList(
            new LogEvent("2026-11-08 10:00:00", "LOGIN_FAILED", "admin"),
            new LogEvent("2026-11-08 10:03:00", "LOGIN_FAILED", "admin"),
            new LogEvent("2026-11-08 10:06:00", "LOGIN_FAILED", "admin")
        );

        List<SecurityAlert> alerts = LogAnalyzer.analyze(events);

        assertEquals(0, alerts.size());
    }

    @Test
    public void shouldNotCombineAttemptsFromDifferentUsers() {

        List<LogEvent> events = Arrays.asList(
            new LogEvent("2026-11-08 10:00:00", "LOGIN_FAILED", "admin"),
            new LogEvent("2026-11-08 10:01:00", "LOGIN_FAILED", "guest"),
            new LogEvent("2026-11-08 10:02:00", "LOGIN_FAILED", "root")
        );

        List<SecurityAlert> alerts = LogAnalyzer.analyze(events);

        assertEquals(0, alerts.size());
    }

    @Test
    public void shouldDetectSuccessfulLoginAfterRepeatedFailures() {

        List<LogEvent> events = Arrays.asList(
            new LogEvent("2026-11-08 10:00:00", "LOGIN_FAILED", "admin"),
            new LogEvent("2026-11-08 10:01:00", "LOGIN_FAILED", "admin"),
            new LogEvent("2026-11-08 10:02:00", "LOGIN_FAILED", "admin"),
            new LogEvent("2026-11-08 10:03:00", "LOGIN_SUCCESS", "admin")
        );

        List<SecurityAlert> alerts = LogAnalyzer.analyze(events);

        assertEquals(2, alerts.size());

        assertEquals(
            "Successful login after repeated failed attempts",
            alerts.get(1).getDescription()
        );

        assertEquals("admin", alerts.get(1).getUsername());
    }
    
    @Test
    public void shouldHandleUnsortedLogEvents() {

        List<LogEvent> events = Arrays.asList(
            new LogEvent("2026-11-08 10:02:00", "LOGIN_FAILED", "admin"),
            new LogEvent("2026-11-08 10:00:00", "LOGIN_FAILED", "admin"),
            new LogEvent("2026-11-08 10:03:00", "LOGIN_SUCCESS", "admin"),
            new LogEvent("2026-11-08 10:01:00", "LOGIN_FAILED", "admin")
        );

        List<SecurityAlert> alerts =
            LogAnalyzer.analyze(events);

        assertEquals(2, alerts.size());

        assertEquals(
            "Possible brute-force login attack",
            alerts.get(0).getDescription()
        );

        assertEquals(
            "Successful login after repeated failed attempts",
            alerts.get(1).getDescription()
        );
    }

}
