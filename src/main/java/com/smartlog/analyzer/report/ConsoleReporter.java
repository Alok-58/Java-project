package com.smartlog.analyzer.report;

import com.smartlog.analyzer.detector.ThreatEngine.AnalysisResult;
import com.smartlog.analyzer.model.AlertSeverity;
import com.smartlog.analyzer.model.SecurityAlert;
import com.smartlog.analyzer.model.ThreatCategory;
import com.smartlog.analyzer.util.AnsiColor;

import java.util.List;
import java.util.Map;

/**
 * Terminal presentation engine producing human-friendly ANSI reports.
 */
public class ConsoleReporter {

    public void printReport(AnalysisResult result) {
        printBanner();
        printOverview(result);
        printSeverityDistribution(result);
        printCategoryBreakdown(result);
        printTopAttackers(result);
        printDetailedAlerts(result);
        printFooter(result);
    }

    private void printBanner() {
        System.out.println(AnsiColor.CYAN + "================================================================================" + AnsiColor.RESET);
        System.out.println(AnsiColor.BOLD_CYAN + "   ____  __  __    _    ____ _____   _     ___   ____     _    _   _ " + AnsiColor.RESET);
        System.out.println(AnsiColor.BOLD_CYAN + "  / ___||  \\/  |  / \\  |  _ \\_   _| | |   / _ \\ / ___|   / \\  | \\ | |" + AnsiColor.RESET);
        System.out.println(AnsiColor.BOLD_CYAN + "  \\___ \\| |\\/| | / _ \\ | |_) || |   | |  | | | | |  _   / _ \\ |  \\| |" + AnsiColor.RESET);
        System.out.println(AnsiColor.BOLD_CYAN + "   ___) | |  | |/ ___ \\|  _ < | |   | |__| |_| | |_| | / ___ \\| |\\  |" + AnsiColor.RESET);
        System.out.println(AnsiColor.BOLD_CYAN + "  |____/|_|  |_/_/   \\_\\_| \\_\\|_|   |_____\\___/ \\____|/_/   \\_\\_| \\_|" + AnsiColor.RESET);
        System.out.println(AnsiColor.DIM + "  Autonomous Server & Firewall Security Incident Correlation Engine" + AnsiColor.RESET);
        System.out.println(AnsiColor.CYAN + "================================================================================" + AnsiColor.RESET);
    }

    private void printOverview(AnalysisResult result) {
        System.out.println("\n" + AnsiColor.BOLD + ">> AUDIT OVERVIEW & TELEMETRY" + AnsiColor.RESET);
        System.out.println("--------------------------------------------------------------------------------");
        System.out.printf("  Target File        : %s%s%s%n", AnsiColor.BOLD_CYAN, result.getFileName(), AnsiColor.RESET);
        System.out.printf("  Detected Format    : %s%n", result.getFormatName());
        System.out.printf("  Total Lines Read   : %,d%n", result.getTotalLines());
        System.out.printf("  Parsed Records     : %,d%n", result.getParsedLines());
        System.out.printf("  Skipped / Comments : %,d%n", result.getSkippedLines());
        long ms = Math.max(1, result.getProcessingDuration().toMillis());
        double throughput = (result.getTotalLines() * 1000.0) / ms;
        System.out.printf("  Execution Time     : %d ms (%,.0f lines/sec)%n", ms, throughput);

        int risk = result.getOverallRiskScore();
        String riskColor = risk >= 70 ? AnsiColor.BOLD_RED : (risk >= 40 ? AnsiColor.BOLD_YELLOW : AnsiColor.BOLD_GREEN);
        String riskLevel = risk >= 70 ? "CRITICAL THREAT" : (risk >= 40 ? "ELEVATED RISK" : "NORMAL / LOW RISK");
        System.out.printf("  Threat Risk Index  : %s[%d / 100] %s%s%n", riskColor, risk, riskLevel, AnsiColor.RESET);
        System.out.printf("  Total Alerts Raised: %s%d%s%n", AnsiColor.BOLD, result.getAlerts().size(), AnsiColor.RESET);
    }

    private void printSeverityDistribution(AnalysisResult result) {
        System.out.println("\n" + AnsiColor.BOLD + ">> SEVERITY BREAKDOWN" + AnsiColor.RESET);
        System.out.println("--------------------------------------------------------------------------------");
        Map<AlertSeverity, Long> counts = result.getSeverityCounts();
        for (AlertSeverity s : AlertSeverity.values()) {
            long count = counts.getOrDefault(s, 0L);
            String bar = "=".repeat((int) Math.min(count * 3, 30));
            System.out.printf("  %-10s [%2d] : %s%s%s%n", s.getLabel(), count, s.getAnsiColor(), bar, AnsiColor.RESET);
        }
    }

    private void printCategoryBreakdown(AnalysisResult result) {
        System.out.println("\n" + AnsiColor.BOLD + ">> DETECTED ATTACK VECTORS" + AnsiColor.RESET);
        System.out.println("--------------------------------------------------------------------------------");
        Map<ThreatCategory, Long> catCounts = result.getCategoryCounts();
        if (catCounts.isEmpty()) {
            System.out.println("  " + AnsiColor.GREEN + "[✓] No threat vectors identified in this dataset." + AnsiColor.RESET);
            return;
        }

        for (Map.Entry<ThreatCategory, Long> entry : catCounts.entrySet()) {
            ThreatCategory cat = entry.getKey();
            System.out.printf("  * %-42s : %2d incident(s) [%s]%n",
                    cat.getTitle(), entry.getValue(), cat.getMitreTechnique());
        }
    }

    private void printTopAttackers(AnalysisResult result) {
        System.out.println("\n" + AnsiColor.BOLD + ">> TOP SOURCE HOSTS BY ACTIVITY" + AnsiColor.RESET);
        System.out.println("--------------------------------------------------------------------------------");
        List<Map.Entry<String, Integer>> top = result.getTopAttackingIps(5);
        if (top.isEmpty()) {
            System.out.println("  No active host telemetry recorded.");
            return;
        }

        int rank = 1;
        for (Map.Entry<String, Integer> e : top) {
            System.out.printf("  #%d  %-20s -> %,d requests / packets%n", rank++, e.getKey(), e.getValue());
        }
    }

    private void printDetailedAlerts(AnalysisResult result) {
        System.out.println("\n" + AnsiColor.BOLD + ">> SECURITY INCIDENT CHRONICLE" + AnsiColor.RESET);
        System.out.println("================================================================================");

        List<SecurityAlert> alerts = result.getAlerts();
        if (alerts.isEmpty()) {
            System.out.println(AnsiColor.GREEN + "  All clean. No malicious patterns matched." + AnsiColor.RESET);
            return;
        }

        int index = 1;
        for (SecurityAlert alert : alerts) {
            String color = alert.getSeverity().getAnsiColor();
            System.out.printf("%n  [%d] %s%s %-8s%s | %s%s%s%n",
                    index++,
                    color, AnsiColor.BOLD, alert.getSeverity().getLabel(), AnsiColor.RESET,
                    AnsiColor.BOLD, alert.getTitle(), AnsiColor.RESET);
            System.out.printf("      Alert ID       : %s%n", alert.getId());
            System.out.printf("      Attacker IP    : %s%s%s%n", AnsiColor.YELLOW, alert.getSourceIp(), AnsiColor.RESET);
            System.out.printf("      MITRE ATT&CK   : %s%n", alert.getMitreTechnique());
            System.out.printf("      Summary        : %s%n", alert.getDescription());
            System.out.printf("      Remediation    : %s%s%s%n", AnsiColor.CYAN, alert.getRecommendation(), AnsiColor.RESET);

            if (!alert.getEvidence().isEmpty()) {
                System.out.println("      Forensic Trace :");
                for (String ev : alert.getEvidence()) {
                    System.out.printf("        %s- %s%s%n", AnsiColor.DIM, ev, AnsiColor.RESET);
                }
            }
        }
    }

    private void printFooter(AnalysisResult result) {
        System.out.println("\n================================================================================");
        System.out.println("  Audit complete. Review critical alerts immediately. Stay vigilant!");
        System.out.println("================================================================================");
    }
}
