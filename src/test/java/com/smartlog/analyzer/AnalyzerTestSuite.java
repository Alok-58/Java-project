package com.smartlog.analyzer;

import com.smartlog.analyzer.detector.BruteForceDetector;
import com.smartlog.analyzer.detector.PortScanDetector;
import com.smartlog.analyzer.detector.WebAttackDetector;
import com.smartlog.analyzer.model.AlertSeverity;
import com.smartlog.analyzer.model.LogEntry;
import com.smartlog.analyzer.model.SecurityAlert;
import com.smartlog.analyzer.model.ThreatCategory;
import com.smartlog.analyzer.parser.ApacheCombinedParser;
import com.smartlog.analyzer.parser.FirewallLogParser;
import com.smartlog.analyzer.parser.LinuxAuthParser;
import com.smartlog.analyzer.threatintel.ThreatIntelligence;
import com.smartlog.analyzer.util.AnsiColor;

import java.time.LocalDateTime;
import java.util.List;

/**
 * Automated regression test suite validating log parsers and threat detection heuristics.
 * Can be executed directly via command line without third-party test runners.
 */
public class AnalyzerTestSuite {

    private static int testsRun = 0;
    private static int testsPassed = 0;
    private static int testsFailed = 0;

    public static void main(String[] args) {
        System.out.println(AnsiColor.BOLD_CYAN + "==========================================================" + AnsiColor.RESET);
        System.out.println(AnsiColor.BOLD_CYAN + "   SMART LOG ANALYZER - AUTOMATED REGRESSION TEST SUITE   " + AnsiColor.RESET);
        System.out.println(AnsiColor.BOLD_CYAN + "==========================================================" + AnsiColor.RESET);

        runTest("Apache Combined Log Parser", AnalyzerTestSuite::testApacheParser);
        runTest("Linux Syslog / Auth Log Parser", AnalyzerTestSuite::testLinuxAuthParser);
        runTest("Firewall Netfilter / iptables Parser", AnalyzerTestSuite::testFirewallParser);
        runTest("SQL Injection (SQLi) Detection", AnalyzerTestSuite::testSqliDetection);
        runTest("Cross-Site Scripting (XSS) Detection", AnalyzerTestSuite::testXssDetection);
        runTest("Directory Traversal Detection", AnalyzerTestSuite::testPathTraversalDetection);
        runTest("SSH Brute-Force Stateful Sliding Window", AnalyzerTestSuite::testBruteForceDetection);
        runTest("Vertical Port Scan Sweep Detection", AnalyzerTestSuite::testPortScanDetection);
        runTest("Threat Intelligence IP Reputation Lookup", AnalyzerTestSuite::testThreatIntel);

        System.out.println("----------------------------------------------------------");
        System.out.printf("Results: %d Run, %s%d Passed%s, %s%d Failed%s%n",
                testsRun,
                AnsiColor.BOLD_GREEN, testsPassed, AnsiColor.RESET,
                testsFailed > 0 ? AnsiColor.BOLD_RED : AnsiColor.RESET, testsFailed, AnsiColor.RESET);

        if (testsFailed > 0) {
            System.err.println(AnsiColor.BOLD_RED + "[!] REGRESSION TESTS FAILED." + AnsiColor.RESET);
            System.exit(1);
        } else {
            System.out.println(AnsiColor.BOLD_GREEN + "[✓] ALL UNIT & HEURISTIC TESTS PASSED SUCCESSFULLY!" + AnsiColor.RESET);
        }
    }

    private static void runTest(String testName, Runnable testMethod) {
        testsRun++;
        try {
            testMethod.run();
            testsPassed++;
            System.out.printf("  %s[PASS]%s %s%n", AnsiColor.BOLD_GREEN, AnsiColor.RESET, testName);
        } catch (Throwable t) {
            testsFailed++;
            System.err.printf("  %s[FAIL]%s %s: %s%n", AnsiColor.BOLD_RED, AnsiColor.RESET, testName, t.getMessage());
            t.printStackTrace(System.err);
        }
    }

    private static void assertTrue(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError("Assertion failed: " + message);
        }
    }

    private static void assertEquals(Object expected, Object actual, String message) {
        if (!expected.equals(actual)) {
            throw new AssertionError(String.format("%s (Expected '%s', but got '%s')", message, expected, actual));
        }
    }

    private static void testApacheParser() {
        ApacheCombinedParser parser = new ApacheCombinedParser();
        String sample = "192.168.1.15 - frank [10/Oct/2026:14:00:01 +0000] \"GET /index.html HTTP/1.1\" 200 4521 \"-\" \"Mozilla/5.0\"";
        assertTrue(parser.canParse(sample), "Parser should recognize Apache format");

        LogEntry entry = parser.parse(sample, 1);
        assertTrue(entry != null, "Entry should parse successfully");
        assertEquals("192.168.1.15", entry.getSourceIp(), "Source IP mismatch");
        assertEquals("GET", entry.getHttpMethod(), "HTTP method mismatch");
        assertEquals("/index.html", entry.getRequestUri(), "URI mismatch");
        assertEquals(200, entry.getStatusCode(), "Status code mismatch");
        assertEquals(4521L, entry.getResponseSizeBytes(), "Response size mismatch");
    }

    private static void testLinuxAuthParser() {
        LinuxAuthParser parser = new LinuxAuthParser();
        String failedLine = "Oct 10 14:02:10 debian-srv sshd[10501]: Failed password for invalid user admin from 203.0.113.55 port 41201 ssh2";
        assertTrue(parser.canParse(failedLine), "Parser should recognize SSH auth line");

        LogEntry entry = parser.parse(failedLine, 5);
        assertTrue(entry != null, "SSH entry should not be null");
        assertEquals("203.0.113.55", entry.getSourceIp(), "Failed SSH IP mismatch");
        assertEquals("admin", entry.getUser(), "Target user mismatch");
        assertEquals("AUTH_FAILED", entry.getAction(), "Action mismatch");
    }

    private static void testFirewallParser() {
        FirewallLogParser parser = new FirewallLogParser();
        String fwLine = "Oct 10 15:01:10 edge-fw kernel: [IPTABLES-DROP] IN=eth0 OUT= SRC=185.220.101.5 DST=10.0.0.2 PROTO=TCP SPT=60001 DPT=21 ACTION=DROP";
        assertTrue(parser.canParse(fwLine), "Parser should recognize iptables line");

        LogEntry entry = parser.parse(fwLine, 3);
        assertTrue(entry != null, "Firewall entry should not be null");
        assertEquals("185.220.101.5", entry.getSourceIp(), "Source IP mismatch");
        assertEquals("10.0.0.2", entry.getDestinationIp(), "Destination IP mismatch");
        assertEquals(21, entry.getDestinationPort(), "Destination port mismatch");
        assertEquals("DROP", entry.getAction(), "Firewall action mismatch");
    }

    private static void testSqliDetection() {
        WebAttackDetector detector = new WebAttackDetector();
        LogEntry entry = LogEntry.builder()
                .lineNumber(1)
                .sourceIp("198.51.100.22")
                .httpMethod("GET")
                .requestUri("/api/products?id=1%20UNION%20SELECT%20null,password%20FROM%20users--")
                .statusCode(200)
                .build();

        detector.process(entry);
        detector.finish();

        List<SecurityAlert> alerts = detector.getAlerts();
        assertTrue(!alerts.isEmpty(), "Should detect SQL Injection");
        assertEquals(ThreatCategory.SQL_INJECTION, alerts.get(0).getCategory(), "Category should be SQL_INJECTION");
    }

    private static void testXssDetection() {
        WebAttackDetector detector = new WebAttackDetector();
        LogEntry entry = LogEntry.builder()
                .lineNumber(2)
                .sourceIp("203.0.113.88")
                .httpMethod("GET")
                .requestUri("/search?q=<script>alert('XSS')</script>")
                .statusCode(200)
                .build();

        detector.process(entry);
        detector.finish();

        List<SecurityAlert> alerts = detector.getAlerts();
        assertTrue(!alerts.isEmpty(), "Should detect XSS");
        assertEquals(ThreatCategory.CROSS_SITE_SCRIPTING, alerts.get(0).getCategory(), "Category should be XSS");
    }

    private static void testPathTraversalDetection() {
        WebAttackDetector detector = new WebAttackDetector();
        LogEntry entry = LogEntry.builder()
                .lineNumber(3)
                .sourceIp("45.146.165.37")
                .httpMethod("GET")
                .requestUri("/download?file=%2e%2e%2f%2e%2e%2fetc%2fpasswd")
                .statusCode(403)
                .build();

        detector.process(entry);
        detector.finish();

        List<SecurityAlert> alerts = detector.getAlerts();
        assertTrue(!alerts.isEmpty(), "Should detect Directory Traversal");
        assertEquals(ThreatCategory.PATH_TRAVERSAL, alerts.get(0).getCategory(), "Category should be PATH_TRAVERSAL");
    }

    private static void testBruteForceDetection() {
        BruteForceDetector detector = new BruteForceDetector(3, 5, java.time.Duration.ofMinutes(5));
        String attackerIp = "203.0.113.55";

        for (int i = 0; i < 4; i++) {
            detector.process(LogEntry.builder()
                    .lineNumber(i + 1)
                    .sourceIp(attackerIp)
                    .user("admin")
                    .action("AUTH_FAILED")
                    .statusCode(401)
                    .timestamp(LocalDateTime.now())
                    .build());
        }

        detector.finish();
        List<SecurityAlert> alerts = detector.getAlerts();
        assertTrue(!alerts.isEmpty(), "Should trigger SSH Brute Force alert");
        assertEquals(ThreatCategory.SSH_BRUTE_FORCE, alerts.get(0).getCategory(), "Threat category should match");
    }

    private static void testPortScanDetection() {
        PortScanDetector detector = new PortScanDetector(3);
        String attackerIp = "185.220.101.5";
        int[] targetPorts = {21, 22, 23, 80, 443};

        for (int port : targetPorts) {
            detector.process(LogEntry.builder()
                    .sourceIp(attackerIp)
                    .destinationPort(port)
                    .protocol("TCP")
                    .action("DROP")
                    .build());
        }

        detector.finish();
        List<SecurityAlert> alerts = detector.getAlerts();
        assertTrue(!alerts.isEmpty(), "Should trigger Port Scan alert");
        assertEquals(ThreatCategory.PORT_SCAN, alerts.get(0).getCategory(), "Threat category should match");
    }

    private static void testThreatIntel() {
        assertTrue(ThreatIntelligence.isKnownMalicious("185.220.101.5"), "Should identify known malicious IP");
        assertTrue(ThreatIntelligence.isTorExitNode("185.220.101.5"), "Should identify known Tor exit node");
        assertTrue(ThreatIntelligence.isKnownScannerUserAgent("sqlmap/1.6.4"), "Should identify sqlmap scanner");
        assertTrue(!ThreatIntelligence.isKnownMalicious("192.168.1.15"), "Clean private IP should not be flagged");
    }
}
