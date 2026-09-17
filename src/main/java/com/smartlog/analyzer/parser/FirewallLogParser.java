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
 * Parser for Linux Netfilter / iptables and firewall packet drop/accept logs.
 * Supports both syslog-style iptables logs and key-value pair firewall entries.
 */
public class FirewallLogParser implements LogParser {

    private static final Pattern SYSLOG_FW_PREFIX = Pattern.compile(
            "^([A-Z][a-z]{2}\\s+\\d+\\s+\\d{2}:\\d{2}:\\d{2})\\s+(\\S+)\\s+kernel:(?:\\s+\\[[^\\]]+\\])?\\s+(.*)$"
    );

    private static final Pattern SRC_IP_PATTERN = Pattern.compile("SRC=([\\d.a-fA-F:]+)");
    private static final Pattern DST_IP_PATTERN = Pattern.compile("DST=([\\d.a-fA-F:]+)");
    private static final Pattern PROTO_PATTERN = Pattern.compile("PROTO=([A-Za-z0-9]+)");
    private static final Pattern SPT_PATTERN = Pattern.compile("SPT=(\\d+)");
    private static final Pattern DPT_PATTERN = Pattern.compile("DPT=(\\d+)");
    private static final Pattern ACTION_PATTERN = Pattern.compile("(DROP|REJECT|BLOCK|ACCEPT|DENIED|ALLOW)", Pattern.CASE_INSENSITIVE);

    @Override
    public LogFormat getSupportedFormat() {
        return LogFormat.FIREWALL_IPTABLES;
    }

    @Override
    public boolean canParse(String sampleLine) {
        if (sampleLine == null || sampleLine.isBlank()) return false;
        String line = sampleLine.trim();
        return (line.contains("SRC=") && line.contains("DST=")) ||
                (line.contains("DPT=") && line.contains("PROTO=")) ||
                line.toUpperCase().contains("IPTABLES");
    }

    @Override
    public LogEntry parse(String line, long lineNumber) {
        if (line == null || line.isBlank()) return null;
        String trimmed = line.trim();

        LocalDateTime timestamp = LocalDateTime.now();
        String messageBody = trimmed;

        Matcher prefixMatcher = SYSLOG_FW_PREFIX.matcher(trimmed);
        if (prefixMatcher.matches()) {
            timestamp = parseSyslogTimestamp(prefixMatcher.group(1));
            messageBody = prefixMatcher.group(3);
        }

        String srcIp = extractGroup(SRC_IP_PATTERN, messageBody, "0.0.0.0");
        String dstIp = extractGroup(DST_IP_PATTERN, messageBody, "0.0.0.0");
        String proto = extractGroup(PROTO_PATTERN, messageBody, "TCP").toUpperCase();
        int srcPort = safeParseInt(extractGroup(SPT_PATTERN, messageBody, "0"), 0);
        int dstPort = safeParseInt(extractGroup(DPT_PATTERN, messageBody, "0"), 0);

        String action = "DROP";
        Matcher actionMatcher = ACTION_PATTERN.matcher(trimmed);
        if (actionMatcher.find()) {
            action = actionMatcher.group(1).toUpperCase();
        }

        return LogEntry.builder()
                .lineNumber(lineNumber)
                .rawLine(trimmed)
                .timestamp(timestamp)
                .sourceIp(srcIp)
                .destinationIp(dstIp)
                .destinationPort(dstPort)
                .protocol(proto)
                .action(action)
                .statusCode(action.equals("ACCEPT") || action.equals("ALLOW") ? 200 : 403)
                .format(LogFormat.FIREWALL_IPTABLES)
                .addMetadata("spt", String.valueOf(srcPort))
                .addMetadata("dpt", String.valueOf(dstPort))
                .build();
    }

    private String extractGroup(Pattern pattern, String text, String fallback) {
        Matcher m = pattern.matcher(text);
        return m.find() ? m.group(1) : fallback;
    }

    private int safeParseInt(String str, int fallback) {
        try {
            return Integer.parseInt(str);
        } catch (NumberFormatException e) {
            return fallback;
        }
    }

    private LocalDateTime parseSyslogTimestamp(String raw) {
        try {
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
}
