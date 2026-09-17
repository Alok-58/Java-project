package com.smartlog.analyzer.parser;

import com.smartlog.analyzer.model.LogFormat;

import java.io.BufferedReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * Factory and detector for selecting the appropriate {@link LogParser} strategy.
 */
public class ParserFactory {

    private final List<LogParser> registeredParsers = new ArrayList<>();

    public ParserFactory() {
        registeredParsers.add(new ApacheCombinedParser());
        registeredParsers.add(new LinuxAuthParser());
        registeredParsers.add(new FirewallLogParser());
    }

    /**
     * Auto-detects the matching parser by inspecting the first few valid lines of the file.
     */
    public LogParser detectParser(Path filePath) throws IOException {
        try (BufferedReader reader = Files.newBufferedReader(filePath)) {
            String line;
            int scanned = 0;
            while ((line = reader.readLine()) != null && scanned < 30) {
                line = line.trim();
                if (line.isEmpty() || line.startsWith("#")) {
                    continue;
                }
                scanned++;
                for (LogParser parser : registeredParsers) {
                    if (parser.canParse(line)) {
                        return parser;
                    }
                }
            }
        }
        // Default to Apache Combined as the most common web log format
        return new ApacheCombinedParser();
    }

    /**
     * Returns a parser explicitly for the given format, or null if unsupported.
     */
    public LogParser getParser(LogFormat format) {
        for (LogParser parser : registeredParsers) {
            if (parser.getSupportedFormat() == format) {
                return parser;
            }
        }
        return new ApacheCombinedParser();
    }
}
