package net.rafalohaki.veloauth.report;

import org.junit.jupiter.api.Test;

import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests for {@link LogReader} proxy-root / log-path resolution.
 * <p>
 * Regression guard for the bug where a <em>relative</em> plugin data directory
 * (e.g. {@code plugins/veloauth}, as Velocity may hand it to plugins) made the
 * two-parents-up walk return {@code null} and silently fall back to the plugin
 * directory — producing {@code plugins/veloauth/logs/latest.log} instead of
 * {@code <proxy-root>/logs/latest.log}.
 */
class LogReaderTest {

    @Test
    void resolveProxyRoot_relativeDataDir_walksToProxyRoot() {
        Path pluginDir = Path.of("plugins", "veloauth");

        Path proxyRoot = LogReader.resolveProxyRoot(pluginDir);

        Path expected = Path.of("plugins", "veloauth").toAbsolutePath().normalize()
                .getParent().getParent();
        assertEquals(expected, proxyRoot,
                () -> "Relative data dir must resolve to the proxy root, got: " + proxyRoot);
        // Must NOT fall back to the plugin directory itself.
        assertTrue(proxyRoot.getFileName() == null || !proxyRoot.endsWith(Path.of("plugins", "veloauth")),
                () -> "Proxy root must not be the plugin directory: " + proxyRoot);
    }

    @Test
    void resolveProxyRoot_absoluteDataDir_walksToProxyRoot() {
        Path pluginDir = Path.of("/srv/velocity/plugins/veloauth");

        Path proxyRoot = LogReader.resolveProxyRoot(pluginDir);

        assertEquals(Path.of("/srv/velocity"), proxyRoot,
                () -> "Absolute data dir must resolve to the proxy root, got: " + proxyRoot);
    }

    @Test
    void resolveLogPath_relativeDataDir_pointsAtProxyRootLogs() {
        Path pluginDir = Path.of("plugins", "veloauth");

        Path logPath = LogReader.resolveLogPath(pluginDir);

        assertTrue(logPath.endsWith(Path.of("logs", "latest.log")),
                () -> "Log path must end with logs/latest.log: " + logPath);
        // The key regression: it must not resolve under the plugin directory.
        assertTrue(!logPath.endsWith(Path.of("plugins", "veloauth", "logs", "latest.log")),
                () -> "Log path must not be under the plugin directory: " + logPath);
    }

    @Test
    void resolveLogPath_absoluteDataDir_pointsAtProxyRootLogs() {
        Path pluginDir = Path.of("/srv/velocity/plugins/veloauth");

        Path logPath = LogReader.resolveLogPath(pluginDir);

        assertEquals(Path.of("/srv/velocity/logs/latest.log"), logPath,
                () -> "Log path must be <proxy-root>/logs/latest.log: " + logPath);
    }
}
