
package com.security.analyzer;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.Assert.assertEquals;
import org.junit.Test;

public class LogReaderTest {

    @Test
    public void shouldReadValidLogEntries() throws IOException {

        Path tempFile = Files.createTempFile("valid-logs", ".log");

        try {
            Files.writeString(tempFile,
                "2026-11-08 10:00:00 LOGIN_SUCCESS user=admin\n" +
                "2026-11-08 10:01:00 LOGIN_FAILED user=guest\n"
            );

            LogReadResult result = LogReader.readLogs(tempFile);

            assertEquals(2, result.getEvents().size());
            assertEquals(0, result.getInvalidLineCount());

        } finally {
            Files.deleteIfExists(tempFile);
        }
    }

    @Test
    public void shouldSkipInvalidLogEntries() throws IOException {

        Path tempFile = Files.createTempFile("mixed-logs", ".log");

        try {
            Files.writeString(tempFile,
                "2026-11-08 10:00:00 LOGIN_SUCCESS user=admin\n" +
                "INVALID LOG ENTRY\n" +
                "2026-11-08 10:02:00 LOGIN_FAILED user=guest\n"
            );

            LogReadResult result = LogReader.readLogs(tempFile);

            assertEquals(2, result.getEvents().size());
            assertEquals(1, result.getInvalidLineCount());
            assertEquals(Integer.valueOf(2),
                result.getInvalidLines().get(0));

        } finally {
            Files.deleteIfExists(tempFile);
        }
    }

    @Test
    public void shouldDetectInvalidTimestamp() throws IOException {

        Path tempFile = Files.createTempFile("timestamp-logs", ".log");

        try {
            Files.writeString(tempFile,
                "2026-13-45 10:00:00 LOGIN_SUCCESS user=admin\n"
            );

            LogReadResult result = LogReader.readLogs(tempFile);

            assertEquals(0, result.getEvents().size());
            assertEquals(1, result.getInvalidLineCount());

        } finally {
            Files.deleteIfExists(tempFile);
        }
    }
    @Test
public void shouldRejectUnknownEventTypes() throws IOException {

    Path tempFile = Files.createTempFile("unknown-event", ".log");

    try {
        Files.writeString(tempFile,
            "2026-11-08 10:00:00 HACK_ATTEMPT user=admin\n"
        );

        LogReadResult result = LogReader.readLogs(tempFile);

        assertEquals(0, result.getEvents().size());
        assertEquals(1, result.getInvalidLineCount());

    } finally {
        Files.deleteIfExists(tempFile);
    }
}
}
