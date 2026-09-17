package com.smartlog.analyzer.parser;

import com.smartlog.analyzer.model.LogEntry;
import com.smartlog.analyzer.model.LogFormat;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.LocalTime;
import java.time.Month;

import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Parser for Linux authentication logs (/var/log/auth.log or /var/log/secure).
 * Identifies SSH authentication attempts, sudo commands, and invalid user probes.
 */
public class LinuxAuthParser implements LogParser {

    // Subpatterns for SSH events
    private static final Pattern BASE_SYSLOG_PATTERN = Pattern.compile(
            "^([A-Z][a-z]{2}\\s+\\d+\\s+\\d{2}:\\d{2}:\\d{2})\\s+(\\S+)\\s+(\\w+)(?:\\[\\d+\\])?:\\s+(.*)$"
    );

    // Subpatterns for SSH events
    private static final Pattern SSH_FAILED_USER = Pattern.compile(
            "Failed password for (?:invalid user )?(\\S+) from ([\\d.a-fA-F:]+) port (\\d+)"
    );

    private static final Pattern SSH_ACCEPTED_USER = Pattern.compile(
            "Accepted (?:password|publickey) for (\\S+) from ([\\d.a-fA-F:]+) port (\\d+)"
    );

    private static final Pattern SUDO_COMMAND = Pattern.compile(
            "\\s*(\\S+)\\s*:\\s*TTY=\\S+\\s*;\\s*PWD=\\S+\\s*;\\s*USER=(\\S+)\\s*;\\s*COMMAND=(.*)"
    );

    @Override
    public LogFormat getSupportedFormat() {
        return LogFormat.LINUX_AUTH;
    }

    @Override
    public boolean canParse(String sampleLine) {
        if (sampleLine == null || sampleLine.isBlank()) return false;
        String line = sampleLine.trim();
        return BASE_SYSLOG_PATTERN.matcher(line).matches() &&
                (line.contains("sshd") || line.contains("sudo") || line.contains("su:") || line.contains("pam_unix"));
    }

    @Override
    public LogEntry parse(String line, long lineNumber) {
        if (line == null || line.isBlank()) return null;
        String trimmed = line.trim();
        Matcher baseMatcher = BASE_SYSLOG_PATTERN.matcher(trimmed);
        if (!baseMatcher.matches()) {
            return null;
        }

        String rawDate = baseMatcher.group(1);
        String program = baseMatcher.group(3);
        String message = baseMatcher.group(4);

        LocalDateTime timestamp = parseSyslogTimestamp(rawDate);
        LogEntry.Builder builder = LogEntry.builder()
                .lineNumber(lineNumber)
                .rawLine(trimmed)
                .timestamp(timestamp)
                .protocol("SSH")
                .format(LogFormat.LINUX_AUTH);

        // Analyze SSH failed logins
        Matcher failedMatcher = SSH_FAILED_USER.matcher(message);
        if (failedMatcher.find()) {
            String user = failedMatcher.group(1);
            String srcIp = failedMatcher.group(2);
            int port = safeParseInt(failedMatcher.group(3), 22);

            return builder
                    .sourceIp(srcIp)
                    .destinationPort(22)
                    .user(user)
                    .action("AUTH_FAILED")
                    .statusCode(401)
                    .addMetadata("service", program)
                    .addMetadata("port", String.valueOf(port))
                    .build();
        }

        // Analyze SSH accepted logins
        Matcher acceptedMatcher = SSH_ACCEPTED_USER.matcher(message);
        if (acceptedMatcher.find()) {
            String user = acceptedMatcher.group(1);
            String srcIp = acceptedMatcher.group(2);
            int port = safeParseInt(acceptedMatcher.group(3), 22);

            return builder
                    .sourceIp(srcIp)
                    .destinationPort(22)
                    .user(user)
                    .action("AUTH_SUCCESS")
                    .statusCode(200)
                    .addMetadata("service", program)
                    .addMetadata("port", String.valueOf(port))
                    .build();
        }

        // Analyze sudo commands
        Matcher sudoMatcher = SUDO_COMMAND.matcher(message);
        if (sudoMatcher.find()) {
            String caller = sudoMatcher.group(1);
            String targetUser = sudoMatcher.group(2);
            String command = sudoMatcher.group(3);

            return builder
                    .sourceIp("127.0.0.1")
                    .user(caller)
                    .action("SUDO_EXEC")
                    .requestUri(command)
                    .statusCode(0)
                    .addMetadata("targetUser", targetUser)
                    .addMetadata("command", command)
                    .build();
        }

        return builder
                .action("INFO")
                .requestUri(message)
                .addMetadata("service", program)
                .build();
    }

    private LocalDateTime parseSyslogTimestamp(String raw) {
        try {
            // Syslog date doesn't include year; infer current year
            String[] parts = raw.trim().split("\\s+");
            if (parts.length >= 3) {
                Month month = Month.valueOf(parts[0].toUpperCase(Locale.ENGLISH));
                int day = Integer.parseInt(parts[1]);
                LocalTime time = LocalTime.parse(parts[2]);
                int year = LocalDate.now().getYear();
                return LocalDateTime.of(LocalDate.of(year, month, day), time);
            }
        } catch (Exception ignored) {}
        return LocalDateTime.now();
    }

    private int safeParseInt(String str, int fallback) {
        try {
            return Integer.parseInt(str);
        } catch (NumberFormatException e) {
            return fallback;
        }
    }
}
