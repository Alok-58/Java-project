# Project Statement: Smart Log Analyzer

## 1. Problem Statement
Modern enterprise infrastructures, web servers, and cloud perimeters produce massive volumes of semi-structured and unstructured event logs (e.g., Apache/Nginx web traffic, Linux `/var/log/auth.log` SSH authentications, and Netfilter/iptables firewall packet traces). During active cyber-attacks or distributed reconnaissance, manual inspection of these logs is virtually impossible due to the sheer volume of data, high false-positive rates, and sophisticated evasion tactics (e.g., URL-encoded exploits, distributed credential stuffing, and stealthy vertical port sweeps).

Without automated, high-throughput log analysis and real-time event correlation, security teams face delayed incident response times (often weeks or months), leading to compromised servers, unauthorized data exfiltration, service disruption, and compliance violations.

## 2. Scope of the Project
The **Smart Log Analyzer** project delivers an autonomous, modular, zero-dependency Java security correlation engine designed to ingest heterogeneous server and network firewall logs, parse them into normalized domain models, correlate events across sliding temporal windows, and detect critical attack vectors.

### In-Scope:
- Multi-format ingestion supporting:
  - Apache / Nginx Combined Log Format (CLF)
  - Linux Syslog / OpenSSH Authentication logs (`/var/log/auth.log`)
  - Linux Netfilter / iptables firewall packet logs (syslog & key-value formats)
- Auto-detection of incoming log formats without requiring manual configuration.
- Stateful detection of:
  - Credential Brute-Force & Password Guessing (SSH & Web endpoints)
  - Web Application Attacks: SQL Injection (SQLi), Cross-Site Scripting (XSS), and Directory / Path Traversal (LFI)
  - Network Reconnaissance / Vertical Port Scanning across firewalls
  - Volumetric Request Rate Anomalies (Scraper bots & Denial of Service bursts)
  - Sensitive configuration probing (`.env`, `.git`, `phpmyadmin`, `id_rsa`)
- Integrated Threat Intelligence indicator lookup (malicious IPs, Tor exit nodes, scanner user-agents).
- Generation of multi-tier audit outputs:
  - High-impact terminal reporting with ANSI color coding and statistical summaries
  - Structured machine-readable JSON exports for SIEM integration
  - Self-contained, responsive HTML/CSS SOC Dashboard
  - Built-in live HTTP web server for zero-configuration browser inspection
- Automated validation test suite covering parsers and heuristics.

### Out-of-Scope (Future Enhancements):
- Deep learning / distributed cluster ingestion across Apache Kafka or Hadoop.
- Direct automated firewall rule enforcement (`iptables -A INPUT -s ... -j DROP`) in dry-run mode.

## 3. Target Users
1. **Security Operations Center (SOC) Analysts**: Requiring quick, automated triage and MITRE ATT&CK correlation of log files during forensic investigations.
2. **System and Network Administrators**: Monitoring server health, detecting unauthorized root/sudo access attempts, and auditing firewall drops.
3. **DevSecOps Engineers**: Integrating lightweight, zero-dependency log audit steps into CI/CD deployment pipelines and staging environment verifications.
4. **Academic Evaluators & Researchers**: Demonstrating practical object-oriented design, regex heuristics, stateful sliding windows, and cybersecurity defense engineering in Java.

## 4. High-Level Features
- **Zero-Dependency Core**: Compiles and runs out-of-the-box on Java 17+ without requiring third-party library downloads or build managers.
- **Strategy Pattern Parsers**: Loose coupling allows straightforward addition of new log formats (e.g., AWS CloudTrail, Windows Event Logs).
- **Temporal Correlation & Sliding Windows**: Aggregates distributed events per IP over time to catch slow-and-low brute-force attacks and port scans.
- **MITRE ATT&CK Mapping**: Every raised alert is tagged with standardized technique identifiers (e.g., T1110, T1190, T1046, T1059, T1083).
- **Interactive SOC Web Dashboard**: Responsive dashboard with severity distributions, top attacker metrics, and real-time client-side search filtering.
- **Embedded Web Server**: Native Java HTTP server providing instant browser access via `-w` / `--web` flag.
