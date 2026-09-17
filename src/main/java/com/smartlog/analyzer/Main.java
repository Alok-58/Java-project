package com.smartlog.analyzer;

import com.smartlog.analyzer.detector.ThreatEngine;
import com.smartlog.analyzer.detector.ThreatEngine.AnalysisResult;
import com.smartlog.analyzer.model.LogFormat;
import com.smartlog.analyzer.parser.LogParser;
import com.smartlog.analyzer.parser.ParserFactory;
import com.smartlog.analyzer.report.ConsoleReporter;
import com.smartlog.analyzer.report.EmbeddedServer;
import com.smartlog.analyzer.report.HtmlDashboardReporter;
import com.smartlog.analyzer.report.JsonReporter;
import com.smartlog.analyzer.util.AnsiColor;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * Main application entrypoint and CLI interface for the Smart Log Analyzer.
 */
public class Main {

    public static void main(String[] args) {
        String logFilePath = null;
        String formatArg = null;
        String jsonOutputPath = null;
        String htmlOutputPath = null;
        boolean startWebServer = false;
        int webPort = 8080;

        for (int i = 0; i < args.length; i++) {
            String arg = args[i];
            if (("--file".equalsIgnoreCase(arg) || "-f".equalsIgnoreCase(arg)) && i + 1 < args.length) {
                logFilePath = args[++i];
            } else if ("--format".equalsIgnoreCase(arg) && i + 1 < args.length) {
                formatArg = args[++i];
            } else if ("--json".equalsIgnoreCase(arg) && i + 1 < args.length) {
                jsonOutputPath = args[++i];
            } else if ("--html".equalsIgnoreCase(arg) && i + 1 < args.length) {
                htmlOutputPath = args[++i];
            } else if ("--web".equalsIgnoreCase(arg) || "-w".equalsIgnoreCase(arg)) {
                startWebServer = true;
            } else if ("--port".equalsIgnoreCase(arg) && i + 1 < args.length) {
                try {
                    webPort = Integer.parseInt(args[++i]);
                } catch (NumberFormatException ignored) {}
            } else if ("--help".equalsIgnoreCase(arg) || "-h".equalsIgnoreCase(arg)) {
                printHelp();
                return;
            }
        }

        // If no file was supplied, check if default sample file exists
        if (logFilePath == null) {
            Path defaultSample = Paths.get("samples", "mixed_security_events.log");
            if (Files.exists(defaultSample)) {
                logFilePath = defaultSample.toString();
                System.out.println(AnsiColor.DIM + "[*] No file specified. Defaulting to sample dataset: " + logFilePath + AnsiColor.RESET);
            } else {
                System.err.println(AnsiColor.BOLD_RED + "Error: Please specify a log file using --file <path>" + AnsiColor.RESET);
                printHelp();
                System.exit(1);
            }
        }

        Path targetPath = Paths.get(logFilePath);
        if (!Files.exists(targetPath)) {
            System.err.println(AnsiColor.BOLD_RED + "Error: Target log file not found: " + targetPath.toAbsolutePath() + AnsiColor.RESET);
            System.exit(1);
        }

        try {
            ParserFactory parserFactory = new ParserFactory();
            LogParser parser;

            if (formatArg != null) {
                LogFormat explicitFormat = switch (formatArg.toLowerCase()) {
                    case "apache", "nginx", "combined" -> LogFormat.APACHE_COMBINED;
                    case "auth", "ssh", "syslog" -> LogFormat.LINUX_AUTH;
                    case "firewall", "iptables" -> LogFormat.FIREWALL_IPTABLES;
                    default -> {
                        System.out.println(AnsiColor.YELLOW + "[!] Unknown format argument '" + formatArg + "', falling back to auto-detection." + AnsiColor.RESET);
                        yield null;
                    }
                };
                parser = (explicitFormat != null) ? parserFactory.getParser(explicitFormat) : parserFactory.detectParser(targetPath);
            } else {
                parser = parserFactory.detectParser(targetPath);
            }

            ThreatEngine engine = new ThreatEngine();
            AnalysisResult result = engine.analyze(targetPath, parser);

            // Print ANSI Console summary
            ConsoleReporter consoleReporter = new ConsoleReporter();
            consoleReporter.printReport(result);

            // Export JSON report if requested
            if (jsonOutputPath != null) {
                Path jsonPath = Paths.get(jsonOutputPath);
                new JsonReporter().writeToFile(result, jsonPath);
                System.out.printf("%n%s[✓] JSON report exported to: %s%s%n",
                        AnsiColor.BOLD_GREEN, jsonPath.toAbsolutePath(), AnsiColor.RESET);
            }

            // Export HTML report if requested
            if (htmlOutputPath != null) {
                Path htmlPath = Paths.get(htmlOutputPath);
                new HtmlDashboardReporter().writeToFile(result, htmlPath);
                System.out.printf("%s[✓] HTML dashboard exported to: %s%s%n",
                        AnsiColor.BOLD_GREEN, htmlPath.toAbsolutePath(), AnsiColor.RESET);
            }

            // Launch embedded live web server if requested
            if (startWebServer) {
                EmbeddedServer server = new EmbeddedServer(result, webPort);
                server.start();
            }

        } catch (Exception e) {
            System.err.println(AnsiColor.BOLD_RED + "[!] Fatal error during log analysis: " + e.getMessage() + AnsiColor.RESET);
            e.printStackTrace();
            System.exit(1);
        }
    }

    private static void printHelp() {
        System.out.println("Usage: java -jar smart-log-analyzer.jar [options]");
        System.out.println("Or:    .\\run.bat [options]");
        System.out.println("\nOptions:");
        System.out.println("  -f, --file <path>        Target server/firewall log file to inspect");
        System.out.println("  --format <type>          Explicit format: apache | auth | firewall (default: auto-detect)");
        System.out.println("  --json <path>            Export full audit findings to JSON file");
        System.out.println("  --html <path>            Generate self-contained HTML visual dashboard report");
        System.out.println("  -w, --web                Launch built-in live HTTP dashboard server");
        System.out.println("  --port <number>          Port for live HTTP server (default: 8080)");
        System.out.println("  -h, --help               Display this help dialog");
    }
}
