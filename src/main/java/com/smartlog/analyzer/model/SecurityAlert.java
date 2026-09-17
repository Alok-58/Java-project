package com.smartlog.analyzer.model;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.UUID;

/**
 * Encapsulates a suspicious security event or anomaly identified by the threat engine.
 */
public class SecurityAlert {
    private final String id;
    private final LocalDateTime timestamp;
    private final ThreatCategory category;
    private final AlertSeverity severity;
    private final String sourceIp;
    private final String title;
    private final String description;
    private final List<String> evidence;
    private final String mitreTechnique;
    private final String recommendation;
    private final int eventCount;

    private SecurityAlert(Builder builder) {
        this.id = builder.id != null ? builder.id : "ALT-" + UUID.randomUUID().toString().substring(0, 8).toUpperCase();
        this.timestamp = builder.timestamp != null ? builder.timestamp : LocalDateTime.now();
        this.category = builder.category;
        this.severity = builder.severity;
        this.sourceIp = builder.sourceIp;
        this.title = builder.title != null ? builder.title : (builder.category != null ? builder.category.getTitle() : "Security Anomaly");
        this.description = builder.description;
        this.evidence = Collections.unmodifiableList(new ArrayList<>(builder.evidence));
        this.mitreTechnique = builder.category != null ? builder.category.getMitreTechnique() : "N/A";
        this.recommendation = builder.recommendation != null ? builder.recommendation : (builder.category != null ? builder.category.getRemediation() : "Investigate source IP.");
        this.eventCount = builder.eventCount > 0 ? builder.eventCount : 1;
    }

    public String getId() { return id; }
    public LocalDateTime getTimestamp() { return timestamp; }
    public ThreatCategory getCategory() { return category; }
    public AlertSeverity getSeverity() { return severity; }
    public String getSourceIp() { return sourceIp; }
    public String getTitle() { return title; }
    public String getDescription() { return description; }
    public List<String> getEvidence() { return evidence; }
    public String getMitreTechnique() { return mitreTechnique; }
    public String getRecommendation() { return recommendation; }
    public int getEventCount() { return eventCount; }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {
        private String id;
        private LocalDateTime timestamp;
        private ThreatCategory category;
        private AlertSeverity severity = AlertSeverity.MEDIUM;
        private String sourceIp = "UNKNOWN";
        private String title;
        private String description;
        private final List<String> evidence = new ArrayList<>();
        private String recommendation;
        private int eventCount = 1;

        public Builder id(String id) { this.id = id; return this; }
        public Builder timestamp(LocalDateTime timestamp) { this.timestamp = timestamp; return this; }
        public Builder category(ThreatCategory category) { this.category = category; return this; }
        public Builder severity(AlertSeverity severity) { this.severity = severity; return this; }
        public Builder sourceIp(String sourceIp) { this.sourceIp = sourceIp; return this; }
        public Builder title(String title) { this.title = title; return this; }
        public Builder description(String description) { this.description = description; return this; }
        public Builder addEvidence(String item) {
            if (item != null) this.evidence.add(item);
            return this;
        }
        public Builder evidence(List<String> items) {
            if (items != null) this.evidence.addAll(items);
            return this;
        }
        public Builder recommendation(String recommendation) { this.recommendation = recommendation; return this; }
        public Builder eventCount(int count) { this.eventCount = count; return this; }

        public SecurityAlert build() {
            return new SecurityAlert(this);
        }
    }

    @Override
    public String toString() {
        return String.format("[%s] [%s] %s - IP: %s (Events: %d) -> %s",
                severity.getLabel(), id, title, sourceIp, eventCount, description);
    }
}
