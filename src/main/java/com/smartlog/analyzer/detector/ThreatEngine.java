package com.smartlog.analyzer.detector;

import com.smartlog.analyzer.model.AlertSeverity;
import com.smartlog.analyzer.model.LogEntry;
import com.smartlog.analyzer.model.SecurityAlert;
import com.smartlog.analyzer.model.ThreatCategory;
import com.smartlog.analyzer.parser.LogParser;

import java.io.BufferedReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Master threat analysis pipeline. Coordinates parsing, dispatches log entries
 * to registered detectors, and computes overall system risk metrics.
 */
public class ThreatEngine {

    private final List<ThreatDetector> detectors = new ArrayList<>();

    public ThreatEngine() {
        // Register default detection plugins
        detectors.add(new BruteForceDetector());
        detectors.add(new WebAttackDetector());
        detectors.add(new PortScanDetector());
        detectors.add(new RateAnomalyDetector());
    }

    public void registerDetector(ThreatDetector detector) {
        if (detector != null) {
            detectors.add(detector);
        }
    }

    /**
     * Executes end-to-end streaming analysis on a given log file.
     */
    public AnalysisResult analyze(Path logFile, LogParser parser) throws IOException {
        Instant startTime = Instant.now();
        resetAll();

        long totalLines = 0;
        long parsedCount = 0;
        long skippedCount = 0;
        Map<String, Integer> ipFrequency = new HashMap<>();

        try (BufferedReader reader = Files.newBufferedReader(logFile)) {
            String line;
            while ((line = reader.readLine()) != null) {
                totalLines++;
                if (line.isBlank() || line.startsWith("#")) {
                    skippedCount++;
                    continue;
                }

                LogEntry entry = parser.parse(line, totalLines);
                if (entry != null) {
                    parsedCount++;
                    if (entry.getSourceIp() != null && !"-".equals(entry.getSourceIp())) {
                        ipFrequency.merge(entry.getSourceIp(), 1, Integer::sum);
                    }
                    for (ThreatDetector detector : detectors) {
                        detector.process(entry);
                    }
                } else {
                    skippedCount++;
                }
            }
        }

        // Finalize stateful detectors
        for (ThreatDetector detector : detectors) {
            detector.finish();
        }

        // Collect all alerts
        List<SecurityAlert> allAlerts = new ArrayList<>();
        for (ThreatDetector detector : detectors) {
            allAlerts.addAll(detector.getAlerts());
        }

        // Sort alerts: CRITICAL first, then HIGH, etc.
        allAlerts.sort((a, b) -> Integer.compare(b.getSeverity().getWeight(), a.getSeverity().getWeight()));

        Instant endTime = Instant.now();
        Duration processingTime = Duration.between(startTime, endTime);

        return new AnalysisResult(
                logFile.getFileName().toString(),
                parser.getSupportedFormat().getDisplayName(),
                totalLines,
                parsedCount,
                skippedCount,
                processingTime,
                allAlerts,
                ipFrequency
        );
    }

    private void resetAll() {
        for (ThreatDetector detector : detectors) {
            detector.reset();
        }
    }

    /**
     * Encapsulates complete analysis metrics and detected alerts.
     */
    public static class AnalysisResult {
        private final String fileName;
        private final String formatName;
        private final long totalLines;
        private final long parsedLines;
        private final long skippedLines;
        private final Duration processingDuration;
        private final List<SecurityAlert> alerts;
        private final Map<String, Integer> ipFrequency;
        private final int overallRiskScore;

        public AnalysisResult(String fileName, String formatName, long totalLines, long parsedLines,
                              long skippedLines, Duration processingDuration,
                              List<SecurityAlert> alerts, Map<String, Integer> ipFrequency) {
            this.fileName = fileName;
            this.formatName = formatName;
            this.totalLines = totalLines;
            this.parsedLines = parsedLines;
            this.skippedLines = skippedLines;
            this.processingDuration = processingDuration;
            this.alerts = Collections.unmodifiableList(alerts);
            this.ipFrequency = Collections.unmodifiableMap(ipFrequency);
            this.overallRiskScore = calculateRiskScore(alerts);
        }

        private int calculateRiskScore(List<SecurityAlert> alerts) {
            if (alerts.isEmpty()) return 0;
            int score = 0;
            for (SecurityAlert alert : alerts) {
                switch (alert.getSeverity()) {
                    case CRITICAL -> score += 35;
                    case HIGH -> score += 20;
                    case MEDIUM -> score += 10;
                    case LOW -> score += 5;
                    case INFO -> score += 1;
                }
            }
            return Math.min(100, score);
        }

        public String getFileName() { return fileName; }
        public String getFormatName() { return formatName; }
        public long getTotalLines() { return totalLines; }
        public long getParsedLines() { return parsedLines; }
        public long getSkippedLines() { return skippedLines; }
        public Duration getProcessingDuration() { return processingDuration; }
        public List<SecurityAlert> getAlerts() { return alerts; }
        public Map<String, Integer> getIpFrequency() { return ipFrequency; }
        public int getOverallRiskScore() { return overallRiskScore; }

        public Map<AlertSeverity, Long> getSeverityCounts() {
            return alerts.stream()
                    .collect(Collectors.groupingBy(SecurityAlert::getSeverity, Collectors.counting()));
        }

        public Map<ThreatCategory, Long> getCategoryCounts() {
            return alerts.stream()
                    .collect(Collectors.groupingBy(SecurityAlert::getCategory, Collectors.counting()));
        }

        public List<Map.Entry<String, Integer>> getTopAttackingIps(int limit) {
            return ipFrequency.entrySet().stream()
                    .sorted((a, b) -> Integer.compare(b.getValue(), a.getValue()))
                    .limit(limit)
                    .collect(Collectors.toList());
        }
    }
}
