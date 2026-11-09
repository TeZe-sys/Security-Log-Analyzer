# Security Log Analyzer

A Java-based cybersecurity tool that analyzes authentication logs, validates log entries, detects suspicious login activity, and generates security analysis reports.

This project is designed as a practical cybersecurity learning project demonstrating Java programming, file handling, regular expressions, log analysis, exception handling, and automated testing.

## Features

- Reads authentication logs from a specified input file.
- Supports configurable input and output file paths.
- Validates timestamps and supported event types.
- Identifies and tracks invalid log entries with their line numbers.
- Detects possible brute-force login activity.
- Detects successful logins following repeated failed attempts.
- Handles empty input files.
- Handles missing or unreadable input files.
- Handles report-generation errors.
- Automatically creates report directories when necessary.
- Generates readable security analysis reports.
- Includes automated unit tests using JUnit.

## Technologies Used

- Java 17+
- Apache Maven
- JUnit 4
- Regular Expressions
- Java NIO File API
- VS Code
- Git and GitHub

## Project Structure

```text
security-log-analyzer/
├── src/
│   ├── main/java/com/security/analyzer/
│   │   ├── App.java
│   │   ├── LogReader.java
│   │   ├── LogReadResult.java
│   │   ├── LogAnalyzer.java
│   │   ├── LogEvent.java
│   │   ├── SecurityAlert.java
│   │   └── ReportGenerator.java
│   └── test/java/com/security/analyzer/
│       ├── LogAnalyzerTest.java
│       └── LogReaderTest.java
├── logs/
│   └── sample.log
├── reports/
├── pom.xml
├── README.md
└── .gitignore
```

## Requirements

Before running this project, install:

- Java Development Kit (JDK) 17 or newer
- Apache Maven 3.9 or newer
- Git

Verify your installations:

```bash
java --version
mvn --version
git --version
```

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/TeZe-sys/Security-Log-Analyzer.git
```

### 2. Open the project directory

```bash
cd Security-Log-Analyzer
```

### 3. Compile the project

```bash
mvn clean compile
```

## Running the Application

### Run with default paths

```bash
mvn exec:java
```

By default, the application reads:

```text
logs/sample.log
```

And generates the report at:

```text
reports/security-report.txt
```

### Run with a custom input file and output file

```bash
mvn exec:java "-Dexec.args=logs/custom-test.log reports/custom-report.txt"
```

You can also provide only an input file:

```bash
mvn exec:java "-Dexec.args=logs/custom-test.log"
```

In that case, the application uses the default report location.

## Supported Log Format

The current version uses a predefined custom authentication log format.

Each valid entry must follow this structure:

```text
YYYY-MM-DD HH:MM:SS EVENT_TYPE user=USERNAME
```

Supported event types:

| Event type | Description |
|---|---|
| LOGIN_SUCCESS | Successful login |
| LOGIN_FAILED | Failed login |
| LOGOUT | User logout |

### Example Input

```text
2026-11-08 10:00:00 LOGIN_SUCCESS user=admin
2026-11-08 10:01:00 LOGIN_FAILED user=guest
2026-11-08 10:02:00 LOGIN_FAILED user=guest
2026-11-08 10:03:00 LOGIN_FAILED user=guest
2026-11-08 10:05:00 LOGIN_SUCCESS user=admin
2026-11-08 10:10:00 LOGOUT user=admin
2026-11-08 10:11:00 LOGIN_FAILED user=admin
```

Invalid entries are skipped during analysis and their line numbers are recorded.

## Detection Rules

The application currently implements two basic detection rules.

### 1. Possible Brute-Force Login Attack

- Tracks failed login attempts separately for each username.
- Three failed attempts within a rolling five-minute window trigger an alert.
- Attempts outside the five-minute window are removed from the tracking window.

### 2. Successful Login After Repeated Failures

- Detects a successful login when at least three recent failed attempts have occurred for the same username.
- Generates an additional security alert.

These rules are heuristic indicators of suspicious activity, not proof of an actual attack.

## Automated Testing

Run the automated test suite:

```bash
mvn clean test
```

The current test suite contains 10 tests:

**LogAnalyzerTest**
- Detects brute-force activity.
- Rejects alerts with fewer than three failed attempts.
- Checks the five-minute time window.
- Keeps different users' attempts separate.
- Detects successful login after repeated failures.
- Handles unsorted log events.

**LogReaderTest**
- Reads valid log entries.
- Skips invalid entries.
- Detects invalid timestamps.
- Rejects unsupported event types.

## Error Handling

The application handles several common situations:

- Missing input file.
- Unreadable input file.
- Empty input file.
- Invalid log entries.
- Report-generation failures.

The application also creates missing parent directories for report output files.

## Current Limitations

- Supports only the predefined custom log format.
- Does not currently parse native Linux authentication logs.
- Does not currently parse Windows Event Logs or EVTX files.
- Uses basic rule-based detection rather than advanced threat detection.
- Does not perform real-time log monitoring.
- Does not include a graphical user interface or database.

## Disclaimer

This project is intended for educational purposes and cybersecurity portfolio demonstration.

Security alerts are based on predefined heuristic rules and should not be treated as confirmation of malicious activity.

Do not use this project as a replacement for a professional SIEM or production security monitoring solution.

Avoid committing real authentication logs containing usernames, IP addresses, or other sensitive information to a public repository.

## Future Improvements

Potential future development includes:

- Linux authentication log parsing.
- More advanced detection rules.
- Additional automated test coverage.
- Improved security reporting.
- Support for additional log formats.

---

**Author:** TeZe

**Repository:** https://github.com/TeZe-sys/Security-Log-Analyzer