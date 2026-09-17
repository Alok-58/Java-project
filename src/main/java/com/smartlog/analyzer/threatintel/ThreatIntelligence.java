package com.smartlog.analyzer.threatintel;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

/**
 * Threat Intelligence repository maintaining known malicious IP indicators,
 * Tor exit nodes, and automated scanner ranges.
 */
public class ThreatIntelligence {

    // Known simulated malicious threat actor IPs (e.g. Tor exit nodes, Mirai botnet IPs, known aggressive scanners)
    private static final Set<String> KNOWN_MALICIOUS_IPS = new HashSet<>();
    private static final Set<String> KNOWN_TOR_NODES = new HashSet<>();
    private static final Set<String> KNOWN_SCANNER_AGENTS = new HashSet<>();

    static {
        // High-risk known attacker IPs
        KNOWN_MALICIOUS_IPS.add("185.220.101.5");
        KNOWN_MALICIOUS_IPS.add("198.51.100.22");
        KNOWN_MALICIOUS_IPS.add("45.146.165.37");
        KNOWN_MALICIOUS_IPS.add("194.26.29.111");
        KNOWN_MALICIOUS_IPS.add("203.0.113.55");

        // Known Tor Exit Nodes
        KNOWN_TOR_NODES.add("185.220.101.5");
        KNOWN_TOR_NODES.add("171.25.193.25");
        KNOWN_TOR_NODES.add("198.51.100.22");

        // Automated scanning tools and vulnerability probes
        KNOWN_SCANNER_AGENTS.add("sqlmap");
        KNOWN_SCANNER_AGENTS.add("nikto");
        KNOWN_SCANNER_AGENTS.add("nmap");
        KNOWN_SCANNER_AGENTS.add("masscan");
        KNOWN_SCANNER_AGENTS.add("gobuster");
        KNOWN_SCANNER_AGENTS.add("dirbuster");
    }

    public static boolean isKnownMalicious(String ip) {
        if (ip == null) return false;
        return KNOWN_MALICIOUS_IPS.contains(ip.trim());
    }

    public static boolean isTorExitNode(String ip) {
        if (ip == null) return false;
        return KNOWN_TOR_NODES.contains(ip.trim());
    }

    public static boolean isKnownScannerUserAgent(String userAgent) {
        if (userAgent == null || userAgent.equals("-")) return false;
        String lower = userAgent.toLowerCase();
        for (String scanner : KNOWN_SCANNER_AGENTS) {
            if (lower.contains(scanner)) {
                return true;
            }
        }
        return false;
    }

    public static Set<String> getKnownMaliciousIps() {
        return Collections.unmodifiableSet(KNOWN_MALICIOUS_IPS);
    }
}
