package com.smartlog.analyzer.report;

import com.smartlog.analyzer.detector.ThreatEngine.AnalysisResult;
import com.smartlog.analyzer.model.AlertSeverity;
import com.smartlog.analyzer.model.SecurityAlert;
import com.smartlog.analyzer.model.ThreatCategory;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

/**
 * Generates an executive, self-contained HTML/CSS Security Operations Dashboard.
 */
public class HtmlDashboardReporter {

    public String generateHtml(AnalysisResult result) {
        StringBuilder html = new StringBuilder();
        int risk = result.getOverallRiskScore();
        String riskColor = risk >= 70 ? "#ef4444" : (risk >= 40 ? "#f59e0b" : "#10b981");
        String riskLabel = risk >= 70 ? "CRITICAL RISK" : (risk >= 40 ? "ELEVATED RISK" : "NORMAL / LOW RISK");

        html.append("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n");
        html.append("  <meta charset=\"UTF-8\">\n");
        html.append("  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n");
        html.append("  <title>Smart Log Analyzer - SOC Threat Audit</title>\n");
        html.append("  <style>\n");
        html.append("    :root { --bg: #0f172a; --panel: #1e293b; --border: #334155; --text: #f8fafc; --text-muted: #94a3b8; --accent: #38bdf8; }\n");
        html.append("    * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; }\n");
        html.append("    body { background-color: var(--bg); color: var(--text); padding: 2rem; line-height: 1.5; }\n");
        html.append("    .container { max-width: 1300px; margin: 0 auto; }\n");
        html.append("    .header { display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border); padding-bottom: 1.5rem; margin-bottom: 2rem; }\n");
        html.append("    .title { font-size: 1.8rem; font-weight: 700; color: #38bdf8; display: flex; align-items: center; gap: 0.75rem; }\n");
        html.append("    .badge { padding: 0.25rem 0.75rem; border-radius: 9999px; font-size: 0.8rem; font-weight: 600; text-transform: uppercase; }\n");
        html.append("    .grid-stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 1.25rem; margin-bottom: 2rem; }\n");
        html.append("    .card { background: var(--panel); border: 1px solid var(--border); border-radius: 0.75rem; padding: 1.25rem; }\n");
        html.append("    .card-title { font-size: 0.85rem; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 0.5rem; }\n");
        html.append("    .card-val { font-size: 2rem; font-weight: 700; }\n");
        html.append("    .card-sub { font-size: 0.8rem; color: var(--text-muted); margin-top: 0.25rem; }\n");
        html.append("    .grid-sections { display: grid; grid-template-columns: 1fr 1fr; gap: 1.5rem; margin-bottom: 2rem; }\n");
        html.append("    @media (max-width: 900px) { .grid-sections { grid-template-columns: 1fr; } }\n");
        html.append("    table { width: 100%; border-collapse: collapse; margin-top: 1rem; font-size: 0.9rem; }\n");
        html.append("    th { text-align: left; padding: 0.75rem 1rem; background: #111827; color: var(--text-muted); font-weight: 600; }\n");
        html.append("    td { padding: 0.75rem 1rem; border-bottom: 1px solid var(--border); }\n");
        html.append("    tr:hover { background: rgba(255,255,255,0.02); }\n");
        html.append("    .sev-CRITICAL { background: #ef4444; color: #fff; }\n");
        html.append("    .sev-HIGH { background: #f97316; color: #fff; }\n");
        html.append("    .sev-MEDIUM { background: #f59e0b; color: #000; }\n");
        html.append("    .sev-LOW { background: #06b6d4; color: #000; }\n");
        html.append("    .sev-INFO { background: #64748b; color: #fff; }\n");
        html.append("    .evidence-box { background: #0b0f19; border: 1px solid #1e293b; border-radius: 0.375rem; padding: 0.5rem; font-family: monospace; font-size: 0.8rem; color: #cbd5e1; margin-top: 0.5rem; }\n");
        html.append("    .search-input { width: 100%; padding: 0.75rem 1rem; background: #0b0f19; border: 1px solid var(--border); border-radius: 0.5rem; color: var(--text); margin-bottom: 1rem; }\n");
        html.append("  </style>\n");
        html.append("</head>\n<body>\n");
        html.append("  <div class=\"container\">\n");

        // Header
        html.append("    <div class=\"header\">\n");
        html.append("      <div>\n");
        html.append("        <h1 class=\"title\">🛡️ Smart Log Security Analyzer</h1>\n");
        html.append("        <p style=\"color: var(--text-muted); font-size: 0.9rem; margin-top: 0.25rem;\">Telemetry Target: <strong>")
                .append(escape(result.getFileName())).append("</strong> &bull; Format: <strong>")
                .append(escape(result.getFormatName())).append("</strong></p>\n");
        html.append("      </div>\n");
        html.append("      <div>\n");
        html.append("        <span class=\"badge\" style=\"background: ").append(riskColor).append("; font-size: 1rem; padding: 0.5rem 1.25rem;\">")
                .append(riskLabel).append(" (").append(risk).append("/100)</span>\n");
        html.append("      </div>\n");
        html.append("    </div>\n");

        // Top Stats Cards
        html.append("    <div class=\"grid-stats\">\n");
        html.append("      <div class=\"card\">\n");
        html.append("        <div class=\"card-title\">Total Log Records</div>\n");
        html.append("        <div class=\"card-val\" style=\"color: #38bdf8;\">").append(String.format("%,d", result.getTotalLines())).append("</div>\n");
        html.append("        <div class=\"card-sub\">").append(result.getParsedLines()).append(" parsed &bull; ").append(result.getSkippedLines()).append(" skipped</div>\n");
        html.append("      </div>\n");

        html.append("      <div class=\"card\">\n");
        html.append("        <div class=\"card-title\">Total Incidents Raised</div>\n");
        html.append("        <div class=\"card-val\" style=\"color: ").append(result.getAlerts().isEmpty() ? "#10b981" : "#f43f5e").append(";\">")
                .append(result.getAlerts().size()).append("</div>\n");
        html.append("        <div class=\"card-sub\">Across ").append(result.getCategoryCounts().size()).append(" threat vectors</div>\n");
        html.append("      </div>\n");

        html.append("      <div class=\"card\">\n");
        html.append("        <div class=\"card-title\">Pipeline Velocity</div>\n");
        long ms = Math.max(1, result.getProcessingDuration().toMillis());
        double rate = (result.getTotalLines() * 1000.0) / ms;
        html.append("        <div class=\"card-val\" style=\"color: #a855f7;\">").append(String.format("%,.0f", rate)).append(" <span style=\"font-size: 1rem;\">lines/s</span></div>\n");
        html.append("        <div class=\"card-sub\">Elapsed time: ").append(ms).append(" ms</div>\n");
        html.append("      </div>\n");

        html.append("      <div class=\"card\">\n");
        html.append("        <div class=\"card-title\">Unique Host IPs</div>\n");
        html.append("        <div class=\"card-val\" style=\"color: #e2e8f0;\">").append(result.getIpFrequency().size()).append("</div>\n");
        html.append("        <div class=\"card-sub\">Active network endpoints</div>\n");
        html.append("      </div>\n");
        html.append("    </div>\n");

        // Middle Section: Severity & Top Attackers
        html.append("    <div class=\"grid-sections\">\n");
        // Severity Card
        html.append("      <div class=\"card\">\n");
        html.append("        <h3 style=\"font-size: 1.1rem; margin-bottom: 1rem;\">📊 Alert Severity Breakdown</h3>\n");
        html.append("        <table>\n");
        html.append("          <thead><tr><th>Severity</th><th>Count</th><th>Percentage</th></tr></thead>\n<tbody>\n");
        Map<AlertSeverity, Long> sevCounts = result.getSeverityCounts();
        int totalAlerts = Math.max(1, result.getAlerts().size());
        for (AlertSeverity s : AlertSeverity.values()) {
            long c = sevCounts.getOrDefault(s, 0L);
            double pct = (c * 100.0) / totalAlerts;
            html.append("          <tr>\n");
            html.append("            <td><span class=\"badge sev-").append(s.getLabel()).append("\">").append(s.getLabel()).append("</span></td>\n");
            html.append("            <td><strong>").append(c).append("</strong></td>\n");
            html.append("            <td>").append(String.format("%.1f%%", pct)).append("</td>\n");
            html.append("          </tr>\n");
        }
        html.append("        </tbody></table>\n");
        html.append("      </div>\n");

        // Top Attackers Card
        html.append("      <div class=\"card\">\n");
        html.append("        <h3 style=\"font-size: 1.1rem; margin-bottom: 1rem;\">🚨 Top Active Hosts</h3>\n");
        html.append("        <table>\n");
        html.append("          <thead><tr><th>#</th><th>IP Address</th><th>Requests</th></tr></thead>\n<tbody>\n");
        List<Map.Entry<String, Integer>> topIps = result.getTopAttackingIps(6);
        int r = 1;
        for (Map.Entry<String, Integer> e : topIps) {
            html.append("          <tr>\n");
            html.append("            <td style=\"color: var(--text-muted);\">#").append(r++).append("</td>\n");
            html.append("            <td><strong style=\"color: #38bdf8;\">").append(escape(e.getKey())).append("</strong></td>\n");
            html.append("            <td>").append(String.format("%,d", e.getValue())).append("</td>\n");
            html.append("          </tr>\n");
        }
        html.append("        </tbody></table>\n");
        html.append("      </div>\n");
        html.append("    </div>\n");

        // Incident Chronicle Table
        html.append("    <div class=\"card\" style=\"margin-bottom: 2rem;\">\n");
        html.append("      <div style=\"display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem;\">\n");
        html.append("        <h3 style=\"font-size: 1.2rem;\">📑 Correlated Security Incidents</h3>\n");
        html.append("      </div>\n");
        html.append("      <input type=\"text\" class=\"search-input\" id=\"filterInput\" onkeyup=\"filterTable()\" placeholder=\"Search incidents by IP, Title, MITRE technique...\">\n");
        html.append("      <table id=\"incidentsTable\">\n");
        html.append("        <thead><tr><th style=\"width: 100px;\">Severity</th><th style=\"width: 140px;\">Source IP</th><th>Threat Summary & Remediation</th><th style=\"width: 180px;\">MITRE ATT&CK</th></tr></thead>\n");
        html.append("        <tbody>\n");

        for (SecurityAlert alert : result.getAlerts()) {
            html.append("          <tr>\n");
            html.append("            <td><span class=\"badge sev-").append(alert.getSeverity().getLabel()).append("\">").append(alert.getSeverity().getLabel()).append("</span></td>\n");
            html.append("            <td><strong style=\"color: #facc15;\">").append(escape(alert.getSourceIp())).append("</strong></td>\n");
            html.append("            <td>\n");
            html.append("              <div style=\"font-weight: 600; font-size: 1rem;\">").append(escape(alert.getTitle())).append("</div>\n");
            html.append("              <div style=\"color: var(--text-muted); margin-top: 0.25rem;\">").append(escape(alert.getDescription())).append("</div>\n");
            html.append("              <div style=\"color: #38bdf8; font-size: 0.85rem; margin-top: 0.25rem;\">💡 <em>Remediation:</em> ").append(escape(alert.getRecommendation())).append("</div>\n");
            if (!alert.getEvidence().isEmpty()) {
                html.append("              <div class=\"evidence-box\">\n");
                for (String ev : alert.getEvidence()) {
                    html.append("                <div>&bull; ").append(escape(ev)).append("</div>\n");
                }
                html.append("              </div>\n");
            }
            html.append("            </td>\n");
            html.append("            <td><span style=\"font-family: monospace; font-size: 0.85rem; color: #a78bfa;\">").append(escape(alert.getMitreTechnique())).append("</span></td>\n");
            html.append("          </tr>\n");
        }
        html.append("        </tbody>\n      </table>\n");
        html.append("    </div>\n");

        // Footer
        html.append("    <div style=\"text-align: center; color: var(--text-muted); font-size: 0.85rem; padding: 1.5rem 0;\">\n");
        html.append("      Generated by Smart Log Analyzer &bull; VITyarthi Project Submission\n");
        html.append("    </div>\n");

        // JavaScript Filter
        html.append("    <script>\n");
        html.append("      function filterTable() {\n");
        html.append("        const filter = document.getElementById('filterInput').value.toLowerCase();\n");
        html.append("        const rows = document.getElementById('incidentsTable').getElementsByTagName('tr');\n");
        html.append("        for (let i = 1; i < rows.length; i++) {\n");
        html.append("          const txt = rows[i].textContent || rows[i].innerText;\n");
        html.append("          rows[i].style.display = txt.toLowerCase().indexOf(filter) > -1 ? '' : 'none';\n");
        html.append("        }\n");
        html.append("      }\n");
        html.append("    </script>\n");

        html.append("  </div>\n</body>\n</html>\n");
        return html.toString();
    }

    public void writeToFile(AnalysisResult result, Path outputPath) throws IOException {
        Files.writeString(outputPath, generateHtml(result));
    }

    private String escape(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&#39;");
    }
}
