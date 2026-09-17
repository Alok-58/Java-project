package com.smartlog.analyzer.parser;

import com.smartlog.analyzer.model.LogEntry;
import com.smartlog.analyzer.model.LogFormat;

/**
 * Strategy interface for parsing unstructured log lines into normalized {@link LogEntry} objects.
 */
public interface LogParser {

    /**
     * @return the log format handled by this parser instance.
     */
    LogFormat getSupportedFormat();

    /**
     * Inspects a sample line to determine if this parser can interpret the given format.
     *
     * @param sampleLine a representative line from the target log file
     * @return true if this parser can handle the format
     */
    boolean canParse(String sampleLine);

    /**
     * Parses an individual log line.
     *
     * @param line raw text line
     * @param lineNumber 1-indexed line position in the source stream
     * @return parsed {@link LogEntry}, or null if the line was empty or unparseable comment
     */
    LogEntry parse(String line, long lineNumber);
}
