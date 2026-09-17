package com.smartlog.analyzer.detector;

import com.smartlog.analyzer.model.AlertSeverity;
import com.smartlog.analyzer.model.LogEntry;
import com.smartlog.analyzer.model.SecurityAlert;
import com.smartlog.analyzer.model.ThreatCategory;

import java.util.*;

/**
 * Heuristic detector for volumetric request spikes, scraper bots, and denial-of-service attempts.
 */
public class RateAnomalyDetector implements ThreatDetector {

    private final int requestCountThreshold;
    private final Map<String, Integer> requestCounts = new HashMap<>();
    private final Map<String, List<String>> samplesByIp = new HashMap<>();
    private final List<SecurityAlert> alerts = new ArrayList<>();

    public RateAnomalyDetector() {
        this(30); // Default threshold: 30 requests in a batch session
    }

    public RateAnomalyDetector(int requestCountThreshold) {
        this.requestCountThreshold = requestCountThreshold;
    }

    @Override
    public String getName() {
        return "Volumetric Request Spike / DoS Detector";
    }

    @Override
    public void process(LogEntry entry) {
        if (entry == null || entry.getSourceIp() == null || entry.getSourceIp().equals("-") || entry.getSourceIp().equals("127.0.0.1")) {
            return;
        }

        String ip = entry.getSourceIp();
        int count = requestCounts.merge(ip, 1, Integer::sum);

        if (count <= 5) {
            List<String> samples = samplesByIp.computeIfAbsent(ip, k -> new ArrayList<>());
            samples.add(String.format("Line %d: [%s] %s %s -> status %d",
                    entry.getLineNumber(), entry.getTimestamp(), entry.getHttpMethod(), entry.getRequestUri(), entry.getStatusCode()));
        }
    }

    @Override
    public void finish() {
        for (Map.Entry<String, Integer> entry : requestCounts.entrySet()) {
            String ip = entry.getKey();
            int count = entry.getValue();

            if (count >= requestCountThreshold) {
                AlertSeverity severity = count >= (requestCountThreshold * 3) ? AlertSeverity.CRITICAL : AlertSeverity.MEDIUM;

                String desc = String.format("Host %s generated an anomalous surge of %d requests, exceeding safe volumetric thresholds.",
                        ip, count);

                alerts.add(SecurityAlert.builder()
                        .category(ThreatCategory.RATE_SPIKE_DOS)
                        .severity(severity)
                        .sourceIp(ip)
                        .title("Volumetric Traffic Spike / Rate Anomaly")
                        .description(desc)
                        .evidence(samplesByIp.getOrDefault(ip, Collections.emptyList()))
                        .eventCount(count)
                        .build());
            }
        }
    }

    @Override
    public List<SecurityAlert> getAlerts() {
        return Collections.unmodifiableList(alerts);
    }

    @Override
    public void reset() {
        requestCounts.clear();
        samplesByIp.clear();
        alerts.clear();
    }
}
