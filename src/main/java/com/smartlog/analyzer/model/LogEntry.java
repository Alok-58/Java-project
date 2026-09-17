package com.smartlog.analyzer.model;

import java.time.LocalDateTime;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Normalized immutable representation of a parsed log record across heterogeneous sources
 * (Apache/Nginx web access, Linux SSH auth, iptables firewall).
 */
public class LogEntry {
    private final long lineNumber;
    private final String rawLine;
    private final LocalDateTime timestamp;
    private final String sourceIp;
    private final String destinationIp;
    private final int destinationPort;
    private final String protocol;
    private final String httpMethod;
    private final String requestUri;
    private final int statusCode;
    private final long responseSizeBytes;
    private final String userAgent;
    private final String user;
    private final String action;
    private final LogFormat format;
    private final Map<String, String> metadata;

    private LogEntry(Builder builder) {
        this.lineNumber = builder.lineNumber;
        this.rawLine = builder.rawLine;
        this.timestamp = builder.timestamp;
        this.sourceIp = builder.sourceIp;
        this.destinationIp = builder.destinationIp;
        this.destinationPort = builder.destinationPort;
        this.protocol = builder.protocol;
        this.httpMethod = builder.httpMethod;
        this.requestUri = builder.requestUri;
        this.statusCode = builder.statusCode;
        this.responseSizeBytes = builder.responseSizeBytes;
        this.userAgent = builder.userAgent;
        this.user = builder.user;
        this.action = builder.action;
        this.format = builder.format != null ? builder.format : LogFormat.UNKNOWN;
        this.metadata = Collections.unmodifiableMap(new HashMap<>(builder.metadata));
    }

    public long getLineNumber() { return lineNumber; }
    public String getRawLine() { return rawLine; }
    public LocalDateTime getTimestamp() { return timestamp; }
    public String getSourceIp() { return sourceIp; }
    public String getDestinationIp() { return destinationIp; }
    public int getDestinationPort() { return destinationPort; }
    public String getProtocol() { return protocol; }
    public String getHttpMethod() { return httpMethod; }
    public String getRequestUri() { return requestUri; }
    public int getStatusCode() { return statusCode; }
    public long getResponseSizeBytes() { return responseSizeBytes; }
    public String getUserAgent() { return userAgent; }
    public String getUser() { return user; }
    public String getAction() { return action; }
    public LogFormat getFormat() { return format; }
    public Map<String, String> getMetadata() { return metadata; }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {
        private long lineNumber;
        private String rawLine = "";
        private LocalDateTime timestamp;
        private String sourceIp = "-";
        private String destinationIp = "-";
        private int destinationPort = 0;
        private String protocol = "-";
        private String httpMethod = "-";
        private String requestUri = "-";
        private int statusCode = 0;
        private long responseSizeBytes = 0;
        private String userAgent = "-";
        private String user = "-";
        private String action = "-";
        private LogFormat format = LogFormat.UNKNOWN;
        private final Map<String, String> metadata = new HashMap<>();

        public Builder lineNumber(long lineNumber) { this.lineNumber = lineNumber; return this; }
        public Builder rawLine(String rawLine) { this.rawLine = rawLine; return this; }
        public Builder timestamp(LocalDateTime timestamp) { this.timestamp = timestamp; return this; }
        public Builder sourceIp(String sourceIp) { this.sourceIp = sourceIp; return this; }
        public Builder destinationIp(String destinationIp) { this.destinationIp = destinationIp; return this; }
        public Builder destinationPort(int port) { this.destinationPort = port; return this; }
        public Builder protocol(String protocol) { this.protocol = protocol; return this; }
        public Builder httpMethod(String httpMethod) { this.httpMethod = httpMethod; return this; }
        public Builder requestUri(String requestUri) { this.requestUri = requestUri; return this; }
        public Builder statusCode(int statusCode) { this.statusCode = statusCode; return this; }
        public Builder responseSizeBytes(long bytes) { this.responseSizeBytes = bytes; return this; }
        public Builder userAgent(String userAgent) { this.userAgent = userAgent; return this; }
        public Builder user(String user) { this.user = user; return this; }
        public Builder action(String action) { this.action = action; return this; }
        public Builder format(LogFormat format) { this.format = format; return this; }
        public Builder addMetadata(String key, String value) {
            if (key != null && value != null) {
                this.metadata.put(key, value);
            }
            return this;
        }

        public LogEntry build() {
            return new LogEntry(this);
        }
    }

    @Override
    public String toString() {
        return String.format("[%s] Line %d (%s) Src: %s -> %s %s (Status: %d)",
                timestamp != null ? timestamp : "N/A",
                lineNumber,
                format,
                sourceIp,
                httpMethod.equals("-") ? action : httpMethod,
                requestUri.equals("-") ? (destinationPort > 0 ? "port:" + destinationPort : "") : requestUri,
                statusCode);
    }
}
