package com.smartlog.analyzer.detector;

import com.smartlog.analyzer.model.AlertSeverity;
import com.smartlog.analyzer.model.LogEntry;
import com.smartlog.analyzer.model.SecurityAlert;
import com.smartlog.analyzer.model.ThreatCategory;
import com.smartlog.analyzer.threatintel.ThreatIntelligence;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.Pattern;

/**
 * Signature and heuristic detector for web application attack vectors including
 * SQL Injection (SQLi), Cross-Site Scripting (XSS), Directory Traversal, and sensitive probes.
 */
public class WebAttackDetector implements ThreatDetector {

    // Regex signatures for SQL Injection
    private static final Pattern SQLI_PATTERN = Pattern.compile(
            "(?i)(\\b(SELECT|UNION|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|TRUNCATE)\\b.*\\b(FROM|INTO|TABLE|DATABASE|WHERE|SET)\\b|" +
            "['\"][\\s]*OR[\\s]+['\"\\d]+[\\s]*=[\\s]*['\"\\d]+|" +
            "['\"][\\s]*OR[\\s]+1=1|" +
            "\\bSLEEP\\s*\\(\\s*\\d+\\s*\\)|" +
            "\\bBENCHMARK\\s*\\(|" +
            "\\bINFORMATION_SCHEMA\\b|" +
            "--[\\s\\r\\n]|/\\*.*\\*/|" +
            "\\bxp_cmdshell\\b)"
    );

    // Regex signatures for Cross-Site Scripting
    private static final Pattern XSS_PATTERN = Pattern.compile(
            "(?i)(<script[^>]*>.*?</script>|" +
            "<script[^>]*>|" +
            "javascript:[^\\s\"'>]+|" +
            "\\bon(?:error|load|click|mouseover|submit|focus)\\s*=|" +
            "alert\\s*\\([^)]*\\)|" +
            "document\\.cookie|" +
            "window\\.location|" +
            "<img[^>]+src=[^>]*on\\w+=)"
    );

    // Regex signatures for Directory Traversal
    private static final Pattern PATH_TRAVERSAL_PATTERN = Pattern.compile(
            "(?i)(\\.\\./|\\.\\.\\\\|%2e%2e%2f|%2e%2e/|\\.\\.%2f|" +
            "/etc/passwd|/etc/shadow|/proc/self|/boot\\.ini|win\\.ini|windows/system32)"
    );

    // Sensitive endpoints frequently targeted by recon scanners
    private static final Set<String> SENSITIVE_PROBES = Set.of(
            "/.env", "/.git", "/.git/config", "/.git/HEAD", "/phpmyadmin",
            "/wp-login.php", "/wp-admin", "/xmlrpc.php", "/config.php.bak",
            "/id_rsa", "/backup.sql", "/dump.sql", "/actuator/env",
            "/console", "/manager/html", "/shell.php"
    );

    // Aggregate findings by IP and Threat Category
    private static class AttackRecord {
        ThreatCategory category;
        AlertSeverity severity;
        String ip;
        int count = 0;
        List<String> evidence = new ArrayList<>();
    }

    private final Map<String, AttackRecord> aggregatedAttacks = new HashMap<>();

    @Override
    public String getName() {
        return "Web Application Attack Detector (SQLi / XSS / LFI)";
    }

    @Override
    public void process(LogEntry entry) {
        if (entry == null || entry.getRequestUri() == null || entry.getRequestUri().equals("-")) {
            return;
        }

        String rawUri = entry.getRequestUri();
        String decodedUri = safeUrlDecode(rawUri);
        String testPayload = rawUri + " " + decodedUri;
        String ip = entry.getSourceIp();

        // 1. SQL Injection check
        if (SQLI_PATTERN.matcher(testPayload).find()) {
            recordAttack(ip, ThreatCategory.SQL_INJECTION, AlertSeverity.CRITICAL,
                    String.format("Line %d: [%s] URI contains SQLi pattern: '%s'",
                            entry.getLineNumber(), entry.getHttpMethod(), rawUri));
            return;
        }

        // 2. Cross-Site Scripting check
        if (XSS_PATTERN.matcher(testPayload).find()) {
            recordAttack(ip, ThreatCategory.CROSS_SITE_SCRIPTING, AlertSeverity.HIGH,
                    String.format("Line %d: [%s] URI contains XSS vector: '%s'",
                            entry.getLineNumber(), entry.getHttpMethod(), rawUri));
            return;
        }

        // 3. Path Traversal check
        if (PATH_TRAVERSAL_PATTERN.matcher(testPayload).find()) {
            recordAttack(ip, ThreatCategory.PATH_TRAVERSAL, AlertSeverity.HIGH,
                    String.format("Line %d: [%s] Path traversal pattern detected: '%s'",
                            entry.getLineNumber(), entry.getHttpMethod(), rawUri));
            return;
        }

        // 4. Sensitive Resource Fuzzing probe
        String lowerDecoded = decodedUri.toLowerCase();
        for (String probe : SENSITIVE_PROBES) {
            if (lowerDecoded.contains(probe)) {
                recordAttack(ip, ThreatCategory.SENSITIVE_RESOURCE_ACCESS, AlertSeverity.MEDIUM,
                        String.format("Line %d: [%s] Probed sensitive file/endpoint: '%s'",
                                entry.getLineNumber(), entry.getHttpMethod(), probe));
                return;
            }
        }

        // 5. Check Scanner User-Agents (e.g. sqlmap, nikto)
        if (ThreatIntelligence.isKnownScannerUserAgent(entry.getUserAgent())) {
            recordAttack(ip, ThreatCategory.SENSITIVE_RESOURCE_ACCESS, AlertSeverity.HIGH,
                    String.format("Line %d: Automated vulnerability scanner user-agent identified: '%s'",
                            entry.getLineNumber(), entry.getUserAgent()));
        }
    }

    private void recordAttack(String ip, ThreatCategory category, AlertSeverity severity, String evidenceLine) {
        String key = ip + "::" + category.name();
        AttackRecord record = aggregatedAttacks.computeIfAbsent(key, k -> {
            AttackRecord ar = new AttackRecord();
            ar.category = category;
            ar.severity = severity;
            ar.ip = ip;
            return ar;
        });

        record.count++;
        if (record.evidence.size() < 5) {
            record.evidence.add(evidenceLine);
        }
    }

    @Override
    public void finish() {
        // Aggregations completed
    }

    @Override
    public List<SecurityAlert> getAlerts() {
        List<SecurityAlert> alerts = new ArrayList<>();
        for (AttackRecord record : aggregatedAttacks.values()) {
            boolean isKnownBad = ThreatIntelligence.isKnownMalicious(record.ip);
            AlertSeverity finalSeverity = (isKnownBad && record.severity == AlertSeverity.HIGH)
                    ? AlertSeverity.CRITICAL : record.severity;

            String desc = String.format("%s attack activity detected from IP %s. Total matches: %d.",
                    record.category.getTitle(), record.ip, record.count);
            if (isKnownBad) {
                desc += " (Identified as known malicious threat actor).";
            }

            alerts.add(SecurityAlert.builder()
                    .category(record.category)
                    .severity(finalSeverity)
                    .sourceIp(record.ip)
                    .title(record.category.getTitle())
                    .description(desc)
                    .evidence(record.evidence)
                    .eventCount(record.count)
                    .build());
        }
        return Collections.unmodifiableList(alerts);
    }

    @Override
    public void reset() {
        aggregatedAttacks.clear();
    }

    private String safeUrlDecode(String input) {
        try {
            return URLDecoder.decode(input, StandardCharsets.UTF_8);
        } catch (Exception e) {
            return input;
        }
    }
}
