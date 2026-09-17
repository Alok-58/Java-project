package com.smartlog.analyzer.model;

/**
 * Enumerates the standard log formats supported by the parser subsystem.
 */
public enum LogFormat {
    APACHE_COMBINED("Apache / Nginx Combined Access Log"),
    LINUX_AUTH("Linux Syslog / Auth Log (/var/log/auth.log)"),
    FIREWALL_IPTABLES("Linux Netfilter / iptables Firewall Log"),
    UNKNOWN("Unknown / Custom Format");

    private final String displayName;

    LogFormat(String displayName) {
        this.displayName = displayName;
    }

    public String getDisplayName() {
        return displayName;
    }
}
