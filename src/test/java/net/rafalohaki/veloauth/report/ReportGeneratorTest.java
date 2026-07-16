package net.rafalohaki.veloauth.report;

import com.velocitypowered.api.proxy.ProxyServer;
import net.rafalohaki.veloauth.VeloAuth;
import net.rafalohaki.veloauth.config.Settings;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.RETURNS_DEEP_STUBS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class ReportGeneratorTest {

    @TempDir
    Path tempDir;

    @Test
    void generate_logsDisabledByDefault_doesNotReadProxyLog() throws Exception {
        Path dataDirectory = createProxyLayout("sensitive-runtime-token");
        Settings settings = new Settings(dataDirectory);
        VeloAuth plugin = pluginMock(dataDirectory);

        String report = new ReportGenerator(plugin, settings).generate().body();

        assertFalse(report.contains("sensitive-runtime-token"));
        assertTrue(report.contains("report.include-logs"));
    }

    @Test
    void generate_logsExplicitlyEnabled_appliesBestEffortRedaction() throws Exception {
        Path dataDirectory = createProxyLayout("Authorization: Bearer sensitive-runtime-token");
        Files.writeString(dataDirectory.resolve("config.yml"), "report:\n  include-logs: true\n");
        Settings settings = new Settings(dataDirectory);
        assertTrue(settings.load());
        VeloAuth plugin = pluginMock(dataDirectory);

        String report = new ReportGenerator(plugin, settings).generate().body();

        assertFalse(report.contains("sensitive-runtime-token"));
        assertTrue(report.contains("Bearer <redacted>"));
    }

    private Path createProxyLayout(String logLine) throws Exception {
        Path dataDirectory = tempDir.resolve("plugins").resolve("veloauth");
        Files.createDirectories(dataDirectory);
        Files.createDirectories(tempDir.resolve("logs"));
        Files.writeString(tempDir.resolve("logs").resolve("latest.log"), logLine);
        return dataDirectory;
    }

    private static VeloAuth pluginMock(Path dataDirectory) {
        VeloAuth plugin = mock(VeloAuth.class);
        ProxyServer server = mock(ProxyServer.class, RETURNS_DEEP_STUBS);
        when(plugin.getDataDirectory()).thenReturn(dataDirectory);
        when(plugin.getServer()).thenReturn(server);
        when(server.getVersion().getVersion()).thenReturn("test");
        when(server.getAllServers()).thenReturn(Set.of());
        when(server.getConfiguration().getAttemptConnectionOrder()).thenReturn(List.of());
        return plugin;
    }
}
