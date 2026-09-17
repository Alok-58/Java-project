package com.smartlog.analyzer.detector;

import com.smartlog.analyzer.model.AlertSeverity;
import com.smartlog.analyzer.model.LogEntry;
import com.smartlog.analyzer.model.SecurityAlert;
import com.smartlog.analyzer.model.ThreatCategory;
import com.smartlog.analyzer.threatintel.ThreatIntelligence;

import java.util.*;

/**
 * Heuristic detector for network reconnaissance and vertical port scanning.
 * Tracks distinct destination ports probed by a single source IP.
 */
public class PortScanDetector implements ThreatDetector {

    private final int portThreshold;
    private final Map<String, Set<Integer>> probedPortsByIp = new HashMap<>();
    private final Map<String, List<String>> scanEvidenceByIp = new HashMap<>();
    private final List<SecurityAlert> alerts = new ArrayList<>();

    public PortScanDetector() {
        this(4); // Trigger alert if >= 4 unique ports are probed by the same IP
    }

    public PortScanDetector(int portThreshold) {
        this.portThreshold = portThreshold;
    }

    @Override
    public String getName() {
        return "Network Port Reconnaissance / Scanner Detector";
    }

    @Override
    public void process(LogEntry entry) {
        if (entry == null || entry.getSourceIp() == null || entry.getSourceIp().equals("-")) {
            return;
        }

        int dport = entry.getDestinationPort();
        if (dport <= 0) {
            return;
        }

        String ip = entry.getSourceIp();
        Set<Integer> ports = probedPortsByIp.computeIfAbsent(ip, k -> new TreeSet<>());
        boolean isNewPort = ports.add(dport);

        if (isNewPort) {
            List<String> evidence = scanEvidenceByIp.computeIfAbsent(ip, k -> new ArrayList<>());
            if (evidence.size() < 6) {
                evidence.add(String.format("Line %d: [%s] Probed port %d/%s (%s)",
                        entry.getLineNumber(), entry.getTimestamp(), dport, entry.getProtocol(), entry.getAction()));
            }
        }
    }

    @Override
    public void finish() {
        for (Map.Entry<String, Set<Integer>> entry : probedPortsByIp.entrySet()) {
            String ip = entry.getKey();
            Set<Integer> ports = entry.getValue();

            if (ports.size() >= portThreshold) {
                boolean isThreatIntelHit = ThreatIntelligence.isKnownMalicious(ip);
                AlertSeverity severity = (ports.size() >= 10 || isThreatIntelHit)
                        ? AlertSeverity.CRITICAL : AlertSeverity.HIGH;

                String desc = String.format("Source IP %s probed %d distinct destination ports %s. Pattern indicates automated port reconnaissance.",
                        ip, ports.size(), ports);

                alerts.add(SecurityAlert.builder()
                        .category(ThreatCategory.PORT_SCAN)
                        .severity(severity)
                        .sourceIp(ip)
                        .title("Vertical Port Sweep / Reconnaissance")
                        .description(desc)
                        .evidence(scanEvidenceByIp.getOrDefault(ip, Collections.emptyList()))
                        .eventCount(ports.size())
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
        probedPortsByIp.clear();
        scanEvidenceByIp.clear();
        alerts.clear();
    }
}
