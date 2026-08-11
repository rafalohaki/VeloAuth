package net.rafalohaki.veloauth.report;

import com.velocitypowered.api.proxy.ProxyServer;
import com.velocitypowered.api.proxy.server.RegisteredServer;
import com.velocitypowered.api.proxy.server.ServerInfo;
import net.rafalohaki.veloauth.BuildConstants;
import net.rafalohaki.veloauth.VeloAuth;
import net.rafalohaki.veloauth.authserver.AuthServerProvider;
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
 *   <li>Optional recent proxy logs (tail, capped at 10 MiB) via {@link LogReader}; omitted by default</li>
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
        return generate(captureOperationSettings());
    }

    Settings.OperationSettings captureOperationSettings() {
        return settings.captureOperationSettings();
    }

    ReportContent generate(Settings.OperationSettings operationSettings) {
        StringBuilder sb = new StringBuilder(64 * 1024);

        appendSection(sb, "VeloAuth version", "v" + BuildConstants.VERSION);
        appendSection(sb, "Velocity version", plugin.getServer().getVersion().getVersion());
        appendSection(sb, "Java version", System.getProperty("java.version"));
        appendSection(sb, "Online mode", String.valueOf(plugin.getServer().getConfiguration().isOnlineMode()));
        appendSection(sb, "Server count", String.valueOf(plugin.getServer().getAllServers().size()));
        appendSection(sb, "Players online", String.valueOf(plugin.getServer().getPlayerCount()));
        appendSection(
                sb,
                "Pending restart changes",
                operationSettings.pendingRestartChanges().isEmpty()
                        ? "none"
                        : String.join(", ", operationSettings.pendingRestartChanges()));

        appendSection(sb, "VeloAuth config.yml (secrets redacted)", readAndRedactPluginConfig());
        appendSection(sb, "velocity.toml (secrets redacted)", readAndRedactVelocityConfig());
        appendSection(sb, "Recent proxy logs", readLogs(operationSettings.report()));

        return new ReportContent(sb.toString(), buildMetadata(operationSettings));
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

    private String readLogs(Settings.ReportSettings reportSettings) {
        if (!reportSettings.includeLogs()) {
            return "[omitted — set report.include-logs: true to include locally redacted logs]";
        }
        Path logPath = LogReader.resolveLogPath(plugin.getDataDirectory());
        Optional<String> logs = LogReader.readTail(logPath);
        return logs.map(ReportRedactor::redactLog)
                .orElse("[log file not found at " + logPath + "]");
    }

    private Path resolveVelocityConfigPath() {
        return LogReader.resolveProxyRoot(plugin.getDataDirectory()).resolve(VELOCITY_CONFIG_RELATIVE);
    }

    private List<McLogsClient.MetadataEntry> buildMetadata(
            Settings.OperationSettings operationSettings) {
        ProxyServer server = plugin.getServer();
        List<McLogsClient.MetadataEntry> meta = new ArrayList<>();
        meta.add(McLogsClient.MetadataEntry.visible("veloauth_version", "v" + BuildConstants.VERSION, "VeloAuth"));
        meta.add(McLogsClient.MetadataEntry.visible("velocity_version", server.getVersion().getVersion(), "Velocity"));
        meta.add(McLogsClient.MetadataEntry.visible("java_version", System.getProperty("java.version"), "Java"));
        meta.add(McLogsClient.MetadataEntry.visible("online_mode", server.getConfiguration().isOnlineMode(), "Online mode"));
        meta.add(McLogsClient.MetadataEntry.visible("server_count", server.getAllServers().size(), "Servers"));
        meta.add(McLogsClient.MetadataEntry.visible("players_online", server.getPlayerCount(), "Players online"));
        meta.add(McLogsClient.MetadataEntry.visible("database_type", settings.getDatabaseStorageType(), "Database"));
        meta.add(McLogsClient.MetadataEntry.visible(
                "ping_timeout_ms", operationSettings.connection().pingTimeoutMillis(), "Ping timeout (ms)"));
        Settings.PremiumSettings premiumSettings = operationSettings.premium();
        meta.add(McLogsClient.MetadataEntry.visible(
                "premium_check", premiumSettings.isCheckEnabled(), "Premium check"));
        meta.add(McLogsClient.MetadataEntry.visible("allow_cracked_on_premium_nicks",
                premiumSettings.isAllowCrackedOnPremiumNicks(), "Allow cracked on premium nicks"));
        meta.add(McLogsClient.MetadataEntry.visible("premium_bypass_auth_server",
                premiumSettings.isBypassAuthServer(), "Premium auth-server bypass"));
        meta.add(McLogsClient.MetadataEntry.visible(
                "pending_restart_changes",
                operationSettings.pendingRestartChanges().isEmpty()
                        ? "none"
                        : String.join(",", operationSettings.pendingRestartChanges()),
                "Pending restart"));
        // Hidden metadata — useful for support but not displayed on the public page.
        AuthServerProvider authServerProvider = plugin.getAuthServerProvider();
        String authServerName = authServerProvider == null
                ? settings.getAuthServerName() : authServerProvider.serverName();
        String authServerMode = authServerProvider == null
                ? settings.getAuthServerMode().getConfigValue()
                : authServerProvider.mode().getConfigValue();
        meta.add(McLogsClient.MetadataEntry.hidden("auth_server", authServerName));
        meta.add(McLogsClient.MetadataEntry.hidden("auth_server_mode", authServerMode));
        if (authServerProvider != null) {
            meta.add(McLogsClient.MetadataEntry.hidden(
                    "auth_server_client_compatibility", authServerProvider.compatibilityDescription()));
        }
        meta.add(McLogsClient.MetadataEntry.hidden("try_list",
                server.getConfiguration().getAttemptConnectionOrder().toString()));
        List<String> serverNames = server.getAllServers().stream()
                .map(RegisteredServer::getServerInfo)
                .map(ServerInfo::getName)
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
