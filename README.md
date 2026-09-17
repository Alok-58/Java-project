# 🛡️ Smart Log Analyzer: Autonomous Threat Detection & Correlation Engine

> A modular, high-throughput, humanized Java security application engineered to ingest, normalize, and correlate heterogeneous server and firewall logs to detect suspicious activities and cyber attacks.

[![Java 17+](https://img.shields.io/badge/Java-17%2B-blue.svg)](https://openjdk.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Build Status](https://img.shields.io/badge/Build-Passing-brightgreen.svg)]()
[![Zero Dependencies](https://img.shields.io/badge/Dependencies-Zero%20(Pure%20JDK)-purple.svg)]()

---

## 1. Project Overview

Modern computing systems generate immense quantities of access, authentication, and firewall logs. Identifying targeted intrusion attempts within gigabytes of log entries is like finding a needle in a haystack. 

The **Smart Log Analyzer** solves this problem by providing an end-to-end security correlation pipeline written in clean, modern Java. It ingests semi-structured log streams (Apache/Nginx web traffic, Linux OpenSSH auth logs, and Netfilter/iptables firewall drops), normalizes them into immutable event records, applies stateful sliding-window heuristics and signature matching, and correlates suspicious activity with MITRE ATT&CK framework techniques.

The project requires **zero external third-party dependencies**—it runs directly on standard Java (JDK 17 or higher) and includes automated test harnesses, realistic attack datasets, Windows batch scripts, and an embedded web dashboard server.

---

## 2. Key Features

- **Multi-Format Ingestion**:
  - Apache / Nginx Combined Log Format (CLF).
  - Linux Syslog / OpenSSH authentication logs (`/var/log/auth.log`).
  - Netfilter / iptables kernel firewall logs.
  - Automatic format detection via sample line heuristic inspection.
- **Stateful Sliding-Window Threat Detection**:
  - **SSH Credential Brute-Force**: Identifies repeated authentication failures targeting system user accounts within configurable time windows.
  - **HTTP Login Spraying**: Detects bursts of HTTP 401/403 unauthorized responses targeting login endpoints.
  - **SQL Injection (SQLi)**: Decodes URL-encoded queries and matches dangerous SQL keywords (`UNION SELECT`, `' OR 1=1`, `WAITFOR DELAY`).
  - **Cross-Site Scripting (XSS)**: Identifies script tags, DOM property access, and client-side execution vectors (`<script>`, `onerror=`, `document.cookie`).
  - **Directory Traversal / LFI**: Intercepts path escapement attempts (`../`, `%2e%2e%2f`, `/etc/passwd`, `win.ini`).
  - **Network Port Reconnaissance**: Heuristically tracks horizontal sweeps and vertical scans across multiple firewall destination ports.
  - **Volumetric Rate Spikes / DoS**: Flags abnormal request surges from scraping bots or aggressive crawlers.
  - **Sensitive File Probing**: Detects recon against `.env`, `.git`, `phpmyadmin`, `id_rsa`, and backup files.
- **Threat Intelligence Enrichment**:
  - Automatically flags IP addresses matching known malicious actors, scanners (`sqlmap`, `nikto`), and Tor exit nodes.
- **Multi-Tier Reporting & Visualization**:
  - **Interactive Terminal UI**: ANSI color-coded summary cards, severity gauges, and forensic traces.
  - **Structured JSON Export**: Full schema output for SIEM ingestion.
  - **SOC HTML Dashboard**: Self-contained, responsive dashboard with interactive client-side search filtering.
  - **Embedded Live HTTP Server**: Launches a lightweight web server on `http://localhost:8080` with zero configuration.

---

## 3. Architecture & Technologies

```
                  ┌─────────────────────────────────┐
                  │ Heterogeneous Log Files (.log)  │
                  └──────────────┬──────────────────┘
                                 │
                                 ▼
                     [ ParserFactory / Detect ]
                                 │
      ┌──────────────────────────┼──────────────────────────┐
      │                          │                          │
      ▼                          ▼                          ▼
ApacheCombinedParser       LinuxAuthParser        FirewallLogParser
      │                          │                          │
      └──────────────────────────┼──────────────────────────┘
                                 │ Normalized LogEntry stream
                                 ▼
                  ┌─────────────────────────────────┐
                  │    ThreatEngine Orchestrator    │
                  └──────────────┬──────────────────┘
                                 │
         ┌───────────────────────┼───────────────────────┐
         ▼                       ▼                       ▼
BruteForceDetector       WebAttackDetector       PortScanDetector
 (Sliding Window)         (Regex + Decoders)      (Recon Sweeps)
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 │ Correlated SecurityAlerts
                                 ▼
         ┌───────────────────────┼───────────────────────┐
         ▼                       ▼                       ▼
   ConsoleReporter         JsonReporter         HtmlDashboardReporter
  (ANSI Terminal UI)      (Machine JSON)         & EmbeddedServer
```

### Technologies Used:
- **Core Platform**: Java SE (JDK 17, 21, or 26)
- **Standard Libraries**:
  - `java.nio.file`: High-throughput non-blocking streaming I/O.
  - `java.util.regex`: Precompiled pattern matchers for attack signatures.
  - `java.time`: Chronological event correlation and sliding windows.
  - `com.sun.net.httpserver`: Lightweight embedded web dashboard server.
- **Build & Execution**: Pure `javac` / batch scripts (`build.bat`, `run.bat`) + standard `pom.xml` for IntelliJ / VS Code.
- **Version Control**: Git

---

## 4. Directory Structure

```
smart-log-analyzer/
├── pom.xml                               # Standard Maven project descriptor
├── build.bat                             # Windows CMD compiler script
├── build.ps1                             # PowerShell compiler script
├── run.bat                               # Windows CMD launcher
├── run.ps1                               # PowerShell launcher
├── test.bat                              # Windows CMD test suite runner
├── test.ps1                              # PowerShell test suite runner
├── statement.md                          # Project Statement & Scope
├── README.md                             # Project Documentation
├── PROJECT_REPORT.md                     # Comprehensive 15-Section Academic Report
├── samples/                              # Realistic synthetic test datasets
│   ├── web_access.log                    # Apache logs with SQLi, XSS, Path Traversal
│   ├── auth_ssh.log                      # Linux SSH logs with Brute Force attack
│   ├── firewall.log                      # Iptables logs with Port Sweep
│   └── mixed_security_events.log         # Complex multi-vector attack scenarios
└── src/
    ├── main/java/com/smartlog/analyzer/
    │   ├── Main.java                     # CLI entrypoint & argument parser
    │   ├── model/                        # Normalized Domain Models
    │   │   ├── LogEntry.java             # Immutable event representation
    │   │   ├── LogFormat.java            # Supported format enum
    │   │   ├── SecurityAlert.java        # Security incident record
    │   │   ├── AlertSeverity.java        # CRITICAL, HIGH, MEDIUM, LOW, INFO
    │   │   └── ThreatCategory.java       # MITRE-mapped threat classifications
    │   ├── parser/                       # Strategy-based Parsing Subsystem
    │   │   ├── LogParser.java            # Parser strategy contract
    │   │   ├── ApacheCombinedParser.java # Apache/Nginx CLF parser
    │   │   ├── LinuxAuthParser.java      # Syslog SSH/auth log parser
    │   │   ├── FirewallLogParser.java    # Netfilter/iptables parser
    │   │   └── ParserFactory.java        # Auto-detection and factory
    │   ├── detector/                     # Threat Correlation Engine
    │   │   ├── ThreatDetector.java       # Detector contract
    │   │   ├── BruteForceDetector.java   # Sliding window auth correlator
    │   │   ├── WebAttackDetector.java    # SQLi, XSS, Path Traversal scanner
    │   │   ├── PortScanDetector.java     # Network sweep detector
    │   │   ├── RateAnomalyDetector.java  # Traffic velocity detector
    │   │   └── ThreatEngine.java         # Master pipeline orchestrator
    │   ├── threatintel/                  # Threat Intelligence
    │   │   └── ThreatIntelligence.java   # Malicious IP & tool signatures
    │   ├── report/                       # Reporting & Visualization
    │   │   ├── ConsoleReporter.java      # Formatted ANSI terminal output
    │   │   ├── JsonReporter.java         # Structured JSON serializer
    │   │   ├── HtmlDashboardReporter.java# Standalone SOC HTML dashboard
    │   │   └── EmbeddedServer.java       # Built-in live web server
    │   └── util/
    │       └── AnsiColor.java            # Terminal color formatting
    └── test/java/com/smartlog/analyzer/
        └── AnalyzerTestSuite.java        # Automated regression test suite
```

---

## 5. Installation & Execution Guide

### Prerequisites
- Java Development Kit (JDK 17 or newer) installed and available in your `PATH`.
  ```powershell
  java -version
  javac -version
  ```

### Step 1: Compile the Project
Run the automated build script:
```powershell
# Using Windows CMD:
.\build.bat

# Or directly using javac:
javac -encoding UTF-8 -d bin src/main/java/com/smartlog/analyzer/*.java src/main/java/com/smartlog/analyzer/*/*.java src/test/java/com/smartlog/analyzer/*.java
```

### Step 2: Run the Analysis Engine
Use `run.bat` or `java -cp bin com.smartlog.analyzer.Main` with your desired flags:

#### 1. Analyze Web Server Access Logs (SQLi / XSS / LFI):
```powershell
.\run.bat -f samples/web_access.log --html report_web.html --json report_web.json
```

#### 2. Analyze Linux SSH Authentication Logs (Brute-Force):
```powershell
.\run.bat -f samples/auth_ssh.log --html report_ssh.html
```

#### 3. Analyze Network Firewall Logs (Port Scans):
```powershell
.\run.bat -f samples/firewall.log --html report_firewall.html
```

#### 4. Analyze Complex Multi-Vector Security Events:
```powershell
.\run.bat -f samples/mixed_security_events.log --html report_mixed.html
```

#### 5. Launch Built-in Live Web Dashboard Server:
```powershell
.\run.bat -f samples/mixed_security_events.log --web --port 8080
```
Then open your browser and navigate to:
👉 **`http://localhost:8080`**

---

## 6. Running Automated Tests

To run the built-in regression test suite (validating all parsers, sliding-window correlations, and attack pattern matchers):

```powershell
# Using Windows CMD:
.\test.bat

# Or directly:
java -cp bin com.smartlog.analyzer.AnalyzerTestSuite
```

### Sample Test Output:
```
==========================================================
   SMART LOG ANALYZER - AUTOMATED REGRESSION TEST SUITE   
==========================================================
  [PASS] Apache Combined Log Parser
  [PASS] Linux Syslog / Auth Log Parser
  [PASS] Firewall Netfilter / iptables Parser
  [PASS] SQL Injection (SQLi) Detection
  [PASS] Cross-Site Scripting (XSS) Detection
  [PASS] Directory Traversal Detection
  [PASS] SSH Brute-Force Stateful Sliding Window
  [PASS] Vertical Port Scan Sweep Detection
  [PASS] Threat Intelligence IP Reputation Lookup
----------------------------------------------------------
Results: 9 Run, 9 Passed, 0 Failed
[✓] ALL UNIT & HEURISTIC TESTS PASSED SUCCESSFULLY!
```

---

## 7. Command-Line Options Reference

| Option | Shorthand | Description | Default |
|---|---|---|---|
| `--file <path>` | `-f` | Path to target log file | `samples/mixed_security_events.log` |
| `--format <type>` | - | Explicit format: `apache`, `auth`, `firewall` | Auto-detect |
| `--html <path>` | - | Generate self-contained HTML SOC dashboard | Disabled |
| `--json <path>` | - | Export audit findings as structured JSON | Disabled |
| `--web` | `-w` | Launch embedded real-time HTTP web server | Disabled |
| `--port <num>` | - | Port for embedded web server | `8080` |
| `--help` | `-h` | Display usage instructions | - |

---

## 8. Sample Terminal Output

```
================================================================================
   ____  __  __    _    ____ _____   _     ___   ____     _    _   _ 
  / ___||  \/  |  / \  |  _ \_   _| | |   / _ \ / ___|   / \  | \ | |
  \___ \| |\/| | / _ \ | |_) || |   | |  | | | | |  _   / _ \ |  \| |
   ___) | |  | |/ ___ \|  _ < | |   | |__| |_| | |_| | / ___ \| |\  |
  |____/|_|  |_/_/   \_\_| \_\|_|   |_____\___/ \____|/_/   \_\_| \_|
  Autonomous Server & Firewall Security Incident Correlation Engine
================================================================================

>> AUDIT OVERVIEW & TELEMETRY
--------------------------------------------------------------------------------
  Target File        : web_access.log
  Detected Format    : Apache / Nginx Combined Access Log
  Total Lines Read   : 19
  Parsed Records     : 19
  Skipped / Comments : 0
  Execution Time     : 59 ms (322 lines/sec)
  Threat Risk Index  : [100 / 100] CRITICAL THREAT
  Total Alerts Raised: 4

>> SEVERITY BREAKDOWN
--------------------------------------------------------------------------------
  CRITICAL   [ 2] : ======
  HIGH       [ 1] : ===
  MEDIUM     [ 1] : ===
  LOW        [ 0] : 
  INFO       [ 0] : 
```

---

## 9. License
This project is open source and available under the [MIT License](LICENSE).
