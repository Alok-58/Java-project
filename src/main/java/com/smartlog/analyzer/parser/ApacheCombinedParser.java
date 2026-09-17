package com.smartlog.analyzer.parser;

import com.smartlog.analyzer.model.LogEntry;
import com.smartlog.analyzer.model.LogFormat;

import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Parser for Apache / Nginx Common and Combined log format.
 * Format: %h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-agent}i"
 */
public class ApacheCombinedParser implements LogParser {

    private static final DateTimeFormatter CLF_DATE_FORMAT =
            DateTimeFormatter.ofPattern("dd/MMM/yyyy:HH:mm:ss Z", Locale.ENGLISH);

    // Matches IP, ident, user, timestamp, request (method, URI, protocol), status, size, referer, user-agent
    private static final Pattern COMBINED_PATTERN = Pattern.compile(
            "^([\\d.a-fA-F:]+)\\s+(\\S+)\\s+(\\S+)\\s+\\[([^\\]]+)\\]\\s+\"(\\S+)(?:\\s+([^\"\\s]+))?(?:\\s+([^\"]+))?\"\\s+(\\d{3}|-)\\s+(\\d+|-)(?:\\s+\"([^\"]*)\"\\s+\"([^\"]*)\")?"
    );

    @Override
    public LogFormat getSupportedFormat() {
        return LogFormat.APACHE_COMBINED;
    }

    @Override
    public boolean canParse(String sampleLine) {
        if (sampleLine == null || sampleLine.isBlank()) return false;
        return COMBINED_PATTERN.matcher(sampleLine.trim()).matches();
    }

    @Override
    public LogEntry parse(String line, long lineNumber) {
        if (line == null || line.isBlank()) return null;
        String trimmed = line.trim();
        Matcher matcher = COMBINED_PATTERN.matcher(trimmed);
        if (!matcher.matches()) {
            return null;
        }

        String ip = matcher.group(1);
        String user = "-".equals(matcher.group(3)) ? "-" : matcher.group(3);
        String rawDate = matcher.group(4);
        String method = matcher.group(5) != null ? matcher.group(5).toUpperCase() : "-";
        String uri = matcher.group(6) != null ? matcher.group(6) : "/";
        String statusStr = matcher.group(8);
        String bytesStr = matcher.group(9);
        String userAgent = (matcher.groupCount() >= 11 && matcher.group(11) != null) ? matcher.group(11) : "-";

        int statusCode = 0;
        try {
            if (statusStr != null && !"-".equals(statusStr)) {
                statusCode = Integer.parseInt(statusStr);
            }
        } catch (NumberFormatException ignored) {}

        long bytes = 0;
        try {
            if (bytesStr != null && !"-".equals(bytesStr)) {
                bytes = Long.parseLong(bytesStr);
            }
        } catch (NumberFormatException ignored) {}

        LocalDateTime timestamp = parseTimestamp(rawDate);

        return LogEntry.builder()
                .lineNumber(lineNumber)
                .rawLine(trimmed)
                .timestamp(timestamp)
                .sourceIp(ip)
                .httpMethod(method)
                .requestUri(uri)
                .statusCode(statusCode)
                .responseSizeBytes(bytes)
                .userAgent(userAgent)
                .user(user)
                .format(LogFormat.APACHE_COMBINED)
                .build();
    }

    private LocalDateTime parseTimestamp(String raw) {
        try {
            OffsetDateTime odt = OffsetDateTime.parse(raw, CLF_DATE_FORMAT);
            return odt.toLocalDateTime();
        } catch (Exception e) {
            return LocalDateTime.now();
        }
    }
}
