
# Security Log Analyzer

A Java-based cybersecurity project that analyzes authentication logs, identifies suspicious login activity, validates log entries, and generates security reports.

## Features

- Reads authentication log files.
- Validates log timestamps and event types.
- Identifies invalid log entries.
- Detects possible brute-force login attacks.
- Detects successful logins after repeated failed attempts.
- Generates security analysis reports.
- Includes automated unit tests using JUnit.

## Technologies Used

- Java 17+
- Maven
- JUnit 4
- VS Code
- Git and GitHub

## Project Structure

```text
security-log-analyzer/
├── src/
│   ├── main/java/com/security/analyzer/
│   └── test/java/com/security/analyzer/
├── logs/
│   └── sample.log
├── reports/
├── pom.xml
└── README.md
```

## How to Run

### 1. Clone the repository

```bash
git clone YOUR_GITHUB_REPOSITORY_URL
```

### 2. Open the project directory

```bash
cd security-log-analyzer
```

### 3. Run tests

```bash
mvn clean test
```

### 4. Run the application

```bash
mvn compile
mvn exec:java -Dexec.mainClass="com.security.analyzer.App"
```

Note: The Maven Exec plugin may need to be added to `pom.xml` before using the last command. Alternatively, run the compiled application using your IDE.

## Detection Rules

- Three failed login attempts within five minutes trigger a possible brute-force alert.
- A successful login after three or more recent failed attempts triggers an additional alert.

## Current Limitations

- Uses a predefined sample log format.
- Does not yet parse native Windows Event Logs or Linux authentication logs.
- Detection rules are basic and intended for learning and demonstration.

## Disclaimer

This project is for educational purposes. It uses sample log data and is not a replacement for a production security monitoring system.
