package com.smartlog.analyzer.report;

import com.smartlog.analyzer.detector.ThreatEngine.AnalysisResult;
import com.smartlog.analyzer.model.SecurityAlert;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

/**
 * Exports telemetry and security alerts to structured JSON format.
 */
public class JsonReporter {

    public String toJson(AnalysisResult result) {
        StringBuilder sb = new StringBuilder();
        sb.append("{\n");
        sb.append("  \"fileName\": \"").append(escape(result.getFileName())).append("\",\n");
        sb.append("  \"detectedFormat\": \"").append(escape(result.getFormatName())).append("\",\n");
        sb.append("  \"totalLines\": ").append(result.getTotalLines()).append(",\n");
        sb.append("  \"parsedLines\": ").append(result.getParsedLines()).append(",\n");
        sb.append("  \"skippedLines\": ").append(result.getSkippedLines()).append(",\n");
        sb.append("  \"executionTimeMs\": ").append(result.getProcessingDuration().toMillis()).append(",\n");
        sb.append("  \"overallRiskScore\": ").append(result.getOverallRiskScore()).append(",\n");
        sb.append("  \"totalAlerts\": ").append(result.getAlerts().size()).append(",\n");

        sb.append("  \"alerts\": [\n");
        List<SecurityAlert> alerts = result.getAlerts();
        for (int i = 0; i < alerts.size(); i++) {
            SecurityAlert a = alerts.get(i);
            sb.append("    {\n");
            sb.append("      \"id\": \"").append(escape(a.getId())).append("\",\n");
            sb.append("      \"severity\": \"").append(escape(a.getSeverity().getLabel())).append("\",\n");
            sb.append("      \"category\": \"").append(escape(a.getCategory().name())).append("\",\n");
            sb.append("      \"title\": \"").append(escape(a.getTitle())).append("\",\n");
            sb.append("      \"sourceIp\": \"").append(escape(a.getSourceIp())).append("\",\n");
            sb.append("      \"mitreTechnique\": \"").append(escape(a.getMitreTechnique())).append("\",\n");
            sb.append("      \"description\": \"").append(escape(a.getDescription())).append("\",\n");
            sb.append("      \"recommendation\": \"").append(escape(a.getRecommendation())).append("\",\n");
            sb.append("      \"evidence\": [");
            List<String> evList = a.getEvidence();
            for (int j = 0; j < evList.size(); j++) {
                sb.append("\"").append(escape(evList.get(j))).append("\"");
                if (j < evList.size() - 1) sb.append(", ");
            }
            sb.append("]\n");
            sb.append("    }").append(i < alerts.size() - 1 ? "," : "").append("\n");
        }
        sb.append("  ]\n");
        sb.append("}\n");
        return sb.toString();
    }

    public void writeToFile(AnalysisResult result, Path outputPath) throws IOException {
        Files.writeString(outputPath, toJson(result));
    }

    private String escape(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\b", "\\b")
                .replace("\f", "\\f")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }
}
