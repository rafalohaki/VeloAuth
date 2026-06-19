package net.rafalohaki.veloauth.report;

import com.velocitypowered.api.proxy.ProxyServer;
import com.velocitypowered.api.proxy.server.RegisteredServer;
import net.rafalohaki.veloauth.BuildConstants;
import net.rafalohaki.veloauth.VeloAuth;
import net.rafalohaki.veloauth.config.Settings;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Assembles the full diagnostic report for {@code /vauth report}:
 * <ul>
 *   <li>VeloAuth {@code config.yml} — secrets redacted via {@link ReportRedactor}</li>
 *   <li>Velocity {@code velocity.toml} — secrets redacted via {@link ReportRedactor}</li>
 *   <li>Recent proxy logs (tail, capped at 10 MiB) via {@link LogReader}</li>
 *   <li>Metadata: VeloAuth/Velocity/Java versions, online-mode, server count, etc.</li>
 * </ul>
 * The assembled text is ready to be uploaded by {@link McLogsClient}.
 * <p>
 * All file I/O here is blocking — callers must run on a virtual thread.
 */
final class ReportGenerator {

    /** Velocity config file, relative to the proxy root. */
    private static final String VELOCITY_CONFIG_RELATIVE = "velocity.toml";

    private final VeloAuth plugin;
    private final Settings settings;

    ReportGenerator(VeloAuth plugin, Settings settings) {
        this.plugin = plugin;
        this.settings = settings;
    }

    /**
     * Builds the full report text and metadata.
     *
     * @return {@link ReportContent} ready for upload
     */
    ReportContent generate() {
        StringBuilder sb = new StringBuilder(64 * 1024);

        appendSection(sb, "VeloAuth version", "v" + BuildConstants.VERSION);
        appendSection(sb, "Velocity version", plugin.getServer().getVersion().getVersion());
        appendSection(sb, "Java version", System.getProperty("java.version"));
        appendSection(sb, "Online mode", String.valueOf(plugin.getServer().getConfiguration().isOnlineMode()));
        appendSection(sb, "Server count", String.valueOf(plugin.getServer().getAllServers().size()));
        appendSection(sb, "Players online", String.valueOf(plugin.getServer().getPlayerCount()));

        appendSection(sb, "VeloAuth config.yml (secrets redacted)", readAndRedactPluginConfig());
        appendSection(sb, "velocity.toml (secrets redacted)", readAndRedactVelocityConfig());
        appendSection(sb, "Recent proxy logs", readLogs());

        return new ReportContent(sb.toString(), buildMetadata());
    }

    private String readAndRedactPluginConfig() {
        Path configFile = settings.getConfigFile();
        if (!Files.isRegularFile(configFile)) {
            return "[config.yml not found at " + configFile + "]";
        }
        try {
            String raw = Files.readString(configFile, StandardCharsets.UTF_8);
            return ReportRedactor.redact(raw);
        } catch (IOException e) {
            return "[failed to read config.yml: " + e.getMessage() + "]";
        }
    }

    private String readAndRedactVelocityConfig() {
        Path velocityConfig = resolveVelocityConfigPath();
        if (!Files.isRegularFile(velocityConfig)) {
            return "[velocity.toml not found at " + velocityConfig + "]";
        }
        try {
            String raw = Files.readString(velocityConfig, StandardCharsets.UTF_8);
            return ReportRedactor.redact(raw);
        } catch (IOException e) {
            return "[failed to read velocity.toml: " + e.getMessage() + "]";
        }
    }

    private String readLogs() {
        Path logPath = LogReader.resolveLogPath(plugin.getDataDirectory());
        Optional<String> logs = LogReader.readTail(logPath);
        return logs.orElse("[log file not found at " + logPath + "]");
    }

    private Path resolveVelocityConfigPath() {
        return LogReader.resolveProxyRoot(plugin.getDataDirectory()).resolve(VELOCITY_CONFIG_RELATIVE);
    }

    private List<McLogsClient.MetadataEntry> buildMetadata() {
        ProxyServer server = plugin.getServer();
        List<McLogsClient.MetadataEntry> meta = new ArrayList<>();
        meta.add(McLogsClient.MetadataEntry.visible("veloauth_version", "v" + BuildConstants.VERSION, "VeloAuth"));
        meta.add(McLogsClient.MetadataEntry.visible("velocity_version", server.getVersion().getVersion(), "Velocity"));
        meta.add(McLogsClient.MetadataEntry.visible("java_version", System.getProperty("java.version"), "Java"));
        meta.add(McLogsClient.MetadataEntry.visible("online_mode", server.getConfiguration().isOnlineMode(), "Online mode"));
        meta.add(McLogsClient.MetadataEntry.visible("server_count", server.getAllServers().size(), "Servers"));
        meta.add(McLogsClient.MetadataEntry.visible("players_online", server.getPlayerCount(), "Players online"));
        meta.add(McLogsClient.MetadataEntry.visible("database_type", settings.getDatabaseStorageType(), "Database"));
        meta.add(McLogsClient.MetadataEntry.visible("ping_timeout_ms", settings.getPingTimeoutMillis(), "Ping timeout (ms)"));
        meta.add(McLogsClient.MetadataEntry.visible("premium_check", settings.isPremiumCheckEnabled(), "Premium check"));
        meta.add(McLogsClient.MetadataEntry.visible("allow_cracked_on_premium_nicks",
                settings.isAllowCrackedOnPremiumNicks(), "Allow cracked on premium nicks"));
        // Hidden metadata — useful for support but not displayed on the public page.
        meta.add(McLogsClient.MetadataEntry.hidden("auth_server", settings.getAuthServerName()));
        meta.add(McLogsClient.MetadataEntry.hidden("try_list",
                server.getConfiguration().getAttemptConnectionOrder().toString()));
        List<String> serverNames = server.getAllServers().stream()
                .map(RegisteredServer::getServerInfo)
                .map(info -> info.getName() + " -> " + info.getAddress())
                .toList();
        meta.add(McLogsClient.MetadataEntry.hidden("servers", String.join(", ", serverNames)));
        return meta;
    }

    private static void appendSection(StringBuilder sb, String title, String body) {
        sb.append("===== ").append(title).append(" =====\n");
        sb.append(body);
        if (!body.endsWith("\n")) {
            sb.append('\n');
        }
        sb.append('\n');
    }

    /** Carrier for the assembled report — the text body and the mclo.gs metadata entries. */
    record ReportContent(String body, List<McLogsClient.MetadataEntry> metadata) {
    }
}
