package com.smartlog.analyzer.report;

import com.smartlog.analyzer.detector.ThreatEngine.AnalysisResult;
import com.smartlog.analyzer.util.AnsiColor;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;

/**
 * Lightweight embedded web server (using standard JDK com.sun.net.httpserver)
 * providing real-time browser dashboard access without external dependencies.
 */
public class EmbeddedServer {

    private final AnalysisResult result;
    private final int port;
    private HttpServer server;

    public EmbeddedServer(AnalysisResult result, int port) {
        this.result = result;
        this.port = port;
    }

    public void start() throws IOException {
        server = HttpServer.create(new InetSocketAddress(port), 0);

        // Serve HTML dashboard
        server.createContext("/", new HttpHandler() {
            @Override
            public void handle(HttpExchange exchange) throws IOException {
                HtmlDashboardReporter dashboard = new HtmlDashboardReporter();
                byte[] responseBytes = dashboard.generateHtml(result).getBytes(StandardCharsets.UTF_8);
                exchange.getResponseHeaders().set("Content-Type", "text/html; charset=UTF-8");
                exchange.sendResponseHeaders(200, responseBytes.length);
                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(responseBytes);
                }
            }
        });

        // Serve JSON raw data endpoint
        server.createContext("/api/alerts", new HttpHandler() {
            @Override
            public void handle(HttpExchange exchange) throws IOException {
                JsonReporter jsonReporter = new JsonReporter();
                byte[] jsonBytes = jsonReporter.toJson(result).getBytes(StandardCharsets.UTF_8);
                exchange.getResponseHeaders().set("Content-Type", "application/json; charset=UTF-8");
                exchange.sendResponseHeaders(200, jsonBytes.length);
                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(jsonBytes);
                }
            }
        });

        server.setExecutor(null);
        server.start();

        System.out.println(AnsiColor.BOLD_GREEN + "\n[✓] Interactive Web Dashboard is LIVE!" + AnsiColor.RESET);
        System.out.printf("    Dashboard URL : %shttp://localhost:%d%s%n", AnsiColor.BOLD_CYAN, port, AnsiColor.RESET);
        System.out.printf("    JSON API URL  : %shttp://localhost:%d/api/alerts%s%n", AnsiColor.BOLD_CYAN, port, AnsiColor.RESET);
        System.out.println("    Press Ctrl+C to terminate the web server.");
    }

    public void stop() {
        if (server != null) {
            server.stop(0);
        }
    }
}
