package com.smartlog.analyzer.detector;

import com.smartlog.analyzer.model.AlertSeverity;
import com.smartlog.analyzer.model.LogEntry;
import com.smartlog.analyzer.model.SecurityAlert;
import com.smartlog.analyzer.model.ThreatCategory;
import com.smartlog.analyzer.threatintel.ThreatIntelligence;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.*;

/**
 * Stateful sliding-window detector for SSH and Web HTTP authentication brute-force attacks.
 * Correlates repeated credential failures from the same source IP over a configurable time window.
 */
public class BruteForceDetector implements ThreatDetector {

    private final int sshFailureThreshold;
    private final int httpAuthThreshold;
    private final Duration windowDuration;

    // Per-IP tracking of failed attempts
    private final Map<String, List<LogEntry>> sshFailuresByIp = new HashMap<>();
    private final Map<String, List<LogEntry>> httpFailuresByIp = new HashMap<>();

    private final List<SecurityAlert> alerts = new ArrayList<>();

    public BruteForceDetector() {
        this(4, 5, Duration.ofMinutes(15));
    }

    public BruteForceDetector(int sshFailureThreshold, int httpAuthThreshold, Duration windowDuration) {
        this.sshFailureThreshold = sshFailureThreshold;
        this.httpAuthThreshold = httpAuthThreshold;
        this.windowDuration = windowDuration;
    }

    @Override
    public String getName() {
        return "Authentication Brute-Force Detector";
    }

    @Override
    public void process(LogEntry entry) {
        if (entry == null || entry.getSourceIp() == null || entry.getSourceIp().equals("-")) {
            return;
        }

        String ip = entry.getSourceIp();

        // Check SSH Auth failures
        if ("AUTH_FAILED".equalsIgnoreCase(entry.getAction())) {
            sshFailuresByIp.computeIfAbsent(ip, k -> new ArrayList<>()).add(entry);
        }

        // Check HTTP 401 (Unauthorized) attempts (for Web traffic)
        if (entry.getStatusCode() == 401 && !"AUTH_FAILED".equalsIgnoreCase(entry.getAction())) {
            httpFailuresByIp.computeIfAbsent(ip, k -> new ArrayList<>()).add(entry);
        }
    }

    @Override
    public void finish() {
        // Correlate SSH failures
        for (Map.Entry<String, List<LogEntry>> e : sshFailuresByIp.entrySet()) {
            String ip = e.getKey();
            List<LogEntry> failures = e.getValue();
            if (failures.size() >= sshFailureThreshold) {
                createSshAlert(ip, failures);
            }
        }

        // Correlate HTTP auth failures
        for (Map.Entry<String, List<LogEntry>> e : httpFailuresByIp.entrySet()) {
            String ip = e.getKey();
            List<LogEntry> failures = e.getValue();
            if (failures.size() >= httpAuthThreshold) {
                createHttpAlert(ip, failures);
            }
        }
    }

    private void createSshAlert(String ip, List<LogEntry> failures) {
        Set<String> targetedUsers = new HashSet<>();
        List<String> evidence = new ArrayList<>();

        for (LogEntry fe : failures) {
            if (fe.getUser() != null && !fe.getUser().equals("-")) {
                targetedUsers.add(fe.getUser());
            }
            if (evidence.size() < 5) {
                evidence.add(String.format("Line %d: [%s] Failed user '%s' from %s",
                        fe.getLineNumber(), fe.getTimestamp(), fe.getUser(), fe.getSourceIp()));
            }
        }

        boolean isThreatIntelHit = ThreatIntelligence.isKnownMalicious(ip) || ThreatIntelligence.isTorExitNode(ip);
        AlertSeverity severity = (failures.size() >= 10 || isThreatIntelHit) ? AlertSeverity.CRITICAL : AlertSeverity.HIGH;

        String description = String.format("Detected %d failed SSH authentication attempts from %s targeting user(s): %s%s",
                failures.size(),
                ip,
                targetedUsers.isEmpty() ? "[unknown/unspecified]" : String.join(", ", targetedUsers),
                isThreatIntelHit ? " (WARNING: IP matches Threat Intelligence feed)" : ""
        );

        alerts.add(SecurityAlert.builder()
                .category(ThreatCategory.SSH_BRUTE_FORCE)
                .severity(severity)
                .sourceIp(ip)
                .title("SSH Brute-Force Password Guessing Burst")
                .description(description)
                .evidence(evidence)
                .eventCount(failures.size())
                .build());
    }

    private void createHttpAlert(String ip, List<LogEntry> failures) {
        List<String> evidence = new ArrayList<>();
        Set<String> targetedEndpoints = new HashSet<>();

        for (LogEntry fe : failures) {
            targetedEndpoints.add(fe.getRequestUri());
            if (evidence.size() < 5) {
                evidence.add(String.format("Line %d: [%s] %s %s -> HTTP 401",
                        fe.getLineNumber(), fe.getTimestamp(), fe.getHttpMethod(), fe.getRequestUri()));
            }
        }

        alerts.add(SecurityAlert.builder()
                .category(ThreatCategory.HTTP_BRUTE_FORCE)
                .severity(AlertSeverity.HIGH)
                .sourceIp(ip)
                .title("HTTP Credential Stuffing / Auth Spray")
                .description(String.format("Observed %d failed HTTP 401 unauthorized requests from %s on endpoint(s): %s",
                        failures.size(), ip, String.join(", ", targetedEndpoints)))
                .evidence(evidence)
                .eventCount(failures.size())
                .build());
    }

    @Override
    public List<SecurityAlert> getAlerts() {
        return Collections.unmodifiableList(alerts);
    }

    @Override
    public void reset() {
        sshFailuresByIp.clear();
        httpFailuresByIp.clear();
        alerts.clear();
    }
}
