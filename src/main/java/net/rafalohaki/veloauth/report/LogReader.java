package net.rafalohaki.veloauth.report;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Optional;

/**
 * Reads the Velocity proxy log file ({@code logs/latest.log}) for inclusion in a
 * {@code /vauth report} upload.
 * <p>
 * Velocity does not expose the proxy working directory or log path through its API, so the
 * path is derived from the plugin data directory: {@code plugins/VeloAuth/../../logs/latest.log}
 * resolves to {@code <proxy-root>/logs/latest.log}. This matches the default Velocity layout
 * and is the same heuristic used by other Velocity plugins that need to read proxy logs.
 * <p>
 * All I/O here is blocking — callers must run on a virtual thread
 * ({@link net.rafalohaki.veloauth.util.VirtualThreadExecutorProvider#getVirtualExecutor()}),
 * never on a Velocity event thread.
 */
final class LogReader {

    private static final Logger logger = LoggerFactory.getLogger(LogReader.class);

    /** Default Velocity log file, relative to the proxy root. */
    private static final String LOG_RELATIVE_PATH = "logs/latest.log";

    /** Hard cap enforced by the mclo.gs API (10 MiB). We stay under it. */
    static final int MAX_LOG_BYTES = 10 * 1024 * 1024;

    /**
     * Resolves the proxy log file path from the plugin data directory.
     *
     * @param pluginDataDirectory the {@code plugins/VeloAuth} directory
     * @return path to {@code <proxy-root>/logs/latest.log}
     */
    static Path resolveLogPath(Path pluginDataDirectory) {
        // plugins/VeloAuth -> plugins -> <proxy-root>
        Path proxyRoot = pluginDataDirectory.getParent() == null
                ? pluginDataDirectory
                : pluginDataDirectory.getParent().getParent();
        if (proxyRoot == null) {
            proxyRoot = pluginDataDirectory;
        }
        return proxyRoot.resolve(LOG_RELATIVE_PATH);
    }

    /**
     * Reads the tail of the proxy log file, capped at {@value #MAX_LOG_BYTES} bytes.
     * If the file is larger than the cap, only the last {@value #MAX_LOG_BYTES} bytes are
     * read so the most recent (and usually most relevant) log lines are preserved.
     *
     * @param logPath path to the log file
     * @return Optional containing the log content (UTF-8), or empty if the file is missing
     *         or unreadable
     */
    static Optional<String> readTail(Path logPath) {
        if (!Files.isRegularFile(logPath)) {
            logger.debug("Log file not found at {}", logPath);
            return Optional.empty();
        }
        try {
            long size = Files.size(logPath);
            if (size <= MAX_LOG_BYTES) {
                return Optional.of(Files.readString(logPath, StandardCharsets.UTF_8));
            }
            // Read only the tail to stay under the API cap.
            byte[] tail = readTailBytes(logPath, MAX_LOG_BYTES);
            String content = new String(tail, StandardCharsets.UTF_8);
            // Drop the likely-partial first line so the report starts on a clean boundary.
            int firstNewline = content.indexOf('\n');
            if (firstNewline > 0 && firstNewline < content.length() - 1) {
                content = content.substring(firstNewline + 1);
            }
            return Optional.of("[log truncated — showing last " + MAX_LOG_BYTES + " bytes]\n" + content);
        } catch (IOException e) {
            logger.warn("Failed to read log file at {}: {}", logPath, e.getMessage());
            return Optional.empty();
        }
    }

    /**
     * Reads the last {@code maxBytes} bytes of a file.
     */
    private static byte[] readTailBytes(Path path, int maxBytes) throws IOException {
        long fileSize = Files.size(path);
        long skip = Math.max(0, fileSize - maxBytes);
        try (var in = Files.newInputStream(path)) {
            long actuallySkipped = in.skip(skip);
            if (actuallySkipped < skip) {
                // Some streams skip less than requested — read past the remainder.
                long remaining = skip - actuallySkipped;
                while (remaining > 0) {
                    int skipped = in.readNBytes((int) Math.min(remaining, 8192)).length;
                    if (skipped == 0) {
                        break;
                    }
                    remaining -= skipped;
                }
            }
            return in.readAllBytes();
        }
    }

    private LogReader() {
    }
}
