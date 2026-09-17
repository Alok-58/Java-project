package com.smartlog.analyzer.model;

/**
 * Severity ranking assigned to security alerts based on attack impact and confidence.
 */
public enum AlertSeverity {
    CRITICAL("CRITICAL", 100, "\u001B[1;31m"), // Bold Red
    HIGH("HIGH", 75, "\u001B[31m"),             // Red
    MEDIUM("MEDIUM", 50, "\u001B[33m"),         // Yellow
    LOW("LOW", 25, "\u001B[36m"),               // Cyan
    INFO("INFO", 10, "\u001B[37m");             // White

    private final String label;
    private final int weight;
    private final String ansiColor;

    AlertSeverity(String label, int weight, String ansiColor) {
        this.label = label;
        this.weight = weight;
        this.ansiColor = ansiColor;
    }

    public String getLabel() {
        return label;
    }

    public int getWeight() {
        return weight;
    }

    public String getAnsiColor() {
        return ansiColor;
    }
}
