package com.smartlog.analyzer.model;

/**
 * Standard classification of detected threats, mapped to MITRE ATT&CK framework techniques.
 */
public enum ThreatCategory {
    SSH_BRUTE_FORCE(
        "SSH Credential Brute-Force",
        "T1110.001 - Password Guessing",
        "Multiple failed SSH authentication attempts detected from source IP in a short time window.",
        "Block IP via fail2ban/firewall, enforce SSH key authentication only, and disable root SSH login."
    ),
    HTTP_BRUTE_FORCE(
        "HTTP Login Brute-Force / Credential Stuffing",
        "T1110.003 - Password Spraying",
        "Surge of 401/403 unauthorized responses targeting web login endpoints.",
        "Implement rate limiting, CAPTCHA challenges, and IP temporary jail for repeated authentication failures."
    ),
    SQL_INJECTION(
        "SQL Injection (SQLi) Attempt",
        "T1190 - Exploit Public-Facing Application",
        "Malicious SQL syntax patterns detected in query parameters or request path.",
        "Use parameterized queries/prepared statements, sanitize inputs, and deploy WAF rules."
    ),
    CROSS_SITE_SCRIPTING(
        "Cross-Site Scripting (XSS) Attempt",
        "T1059.007 - JavaScript Execution / Client-Side Injection",
        "Embedded script tags or javascript/event handlers detected in request payload.",
        "Implement context-aware output encoding, validate inputs, and deploy strict Content Security Policy (CSP)."
    ),
    PATH_TRAVERSAL(
        "Directory / Path Traversal Probe",
        "T1083 - File and Directory Discovery",
        "Directory navigation patterns ('../' or encoded equivalents) probing sensitive system files.",
        "Restrict web server file access root, reject dot-dot patterns, and use strict whitelisting for file downloads."
    ),
    SENSITIVE_RESOURCE_ACCESS(
        "Sensitive File / Endpoint Fuzzing",
        "T1595.002 - Vulnerability Scanning",
        "Probing for sensitive configuration files (.env, .git, phpmyadmin, wp-login, backup dumps).",
        "Deny public access to hidden and administrative directories in server configuration."
    ),
    PORT_SCAN(
        "Network Port Reconnaissance / Sweep",
        "T1046 - Network Service Discovery",
        "Systematic connection attempts across multiple ports or rapid blocked packets.",
        "Drop reconnaissance traffic with firewall rules (iptables/nftables) and enable port knocking if necessary."
    ),
    RATE_SPIKE_DOS(
        "Volumetric Request Spike / Potential DoS",
        "T1499.002 - Endpoint Denial of Service",
        "Anomalous high-velocity request traffic originating from a single host.",
        "Enable upstream DDoS mitigation, apply rate limiting (e.g. Nginx limit_req), and configure CDN shielding."
    ),
    SUSPICIOUS_IP_REPUTATION(
        "Known Threat Actor / Tor Exit Node Traffic",
        "T1584.004 - Compromised Infrastructure: Server",
        "Traffic matching known malicious IP addresses, scanners, or anonymous proxies.",
        "Monitor closely, verify origin headers, or enforce geo-blocking/threat feed IP drops."
    );

    private final String title;
    private final String mitreTechnique;
    private final String description;
    private final String remediation;

    ThreatCategory(String title, String mitreTechnique, String description, String remediation) {
        this.title = title;
        this.mitreTechnique = mitreTechnique;
        this.description = description;
        this.remediation = remediation;
    }

    public String getTitle() {
        return title;
    }

    public String getMitreTechnique() {
        return mitreTechnique;
    }

    public String getDescription() {
        return description;
    }

    public String getRemediation() {
        return remediation;
    }
}
