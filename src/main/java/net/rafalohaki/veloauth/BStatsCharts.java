package net.rafalohaki.veloauth;

import com.velocitypowered.api.network.ProtocolVersion;
import com.velocitypowered.api.proxy.Player;
import com.velocitypowered.api.proxy.ProxyServer;
import net.rafalohaki.veloauth.config.Settings;
import net.rafalohaki.veloauth.database.DatabaseType;
import net.rafalohaki.veloauth.i18n.BuiltInLanguages;
import org.bstats.charts.AdvancedPie;
import org.bstats.charts.SimplePie;
import org.bstats.velocity.Metrics;

import java.util.Collection;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;

/** Registers bounded, aggregate bStats charts without player or operator identifiers. */
final class BStatsCharts {

    static final int CHART_COUNT = 7;
    static final String UNKNOWN_CLIENT_VERSION = "Unknown";

    private static final String CLIENT_VERSIONS_CHART_ID = "client_versions";
    private static final String AUTH_SERVER_MODE_CHART_ID = "auth_server_mode";
    private static final String DATABASE_BACKEND_CHART_ID = "database_backend";
    private static final String LANGUAGE_CHART_ID = "language";
    private static final String PREMIUM_ROUTING_CHART_ID = "premium_routing";
    private static final String FLOODGATE_ROUTING_CHART_ID = "floodgate_routing";
    private static final String TWO_FACTOR_SUPPORT_CHART_ID = "two_factor_support";
    private static final String ENABLED_CATEGORY = "enabled";
    private static final String DISABLED_CATEGORY = "disabled";
    private static final String AUTH_SERVER_CATEGORY = "auth-server";
    private static final String VERIFIED_BYPASS_CATEGORY = "verified-bypass";

    private BStatsCharts() {
    }

    static void register(Metrics metrics, ProxyServer proxyServer, Settings settings) {
        Objects.requireNonNull(metrics, "metrics");
        Objects.requireNonNull(proxyServer, "proxyServer");
        Objects.requireNonNull(settings, "settings");

        // Restart-scoped settings are captured once so /vauth reload cannot make telemetry claim
        // that an unapplied topology or database change is already active.
        String activeAuthServerMode = settings.getAuthServerMode().getConfigValue();
        String activeDatabaseBackend = databaseBackend(settings);

        metrics.addCustomChart(new AdvancedPie(CLIENT_VERSIONS_CHART_ID,
                () -> clientVersionCounts(proxyServer.getAllPlayers())));
        metrics.addCustomChart(new SimplePie(AUTH_SERVER_MODE_CHART_ID, () -> activeAuthServerMode));
        metrics.addCustomChart(new SimplePie(DATABASE_BACKEND_CHART_ID, () -> activeDatabaseBackend));
        metrics.addCustomChart(new SimplePie(LANGUAGE_CHART_ID, () -> language(settings)));
        metrics.addCustomChart(new SimplePie(PREMIUM_ROUTING_CHART_ID, () -> premiumRouting(settings)));
        metrics.addCustomChart(new SimplePie(FLOODGATE_ROUTING_CHART_ID, () -> floodgateRouting(settings)));
        metrics.addCustomChart(new SimplePie(TWO_FACTOR_SUPPORT_CHART_ID, () -> twoFactorSupport(settings)));
    }

    static Map<String, Integer> clientVersionCounts(Collection<Player> players) {
        Objects.requireNonNull(players, "players");
        Map<String, Integer> result = new TreeMap<>();
        for (Player player : players) {
            String version = clientVersion(player);
            result.merge(version, 1, Integer::sum);
        }
        return result;
    }

    static String databaseBackend(Settings settings) {
        DatabaseType databaseType = DatabaseType.fromName(settings.getDatabaseStorageType());
        return databaseType == null ? "OTHER" : databaseType.getName();
    }

    static String language(Settings settings) {
        String configuredLanguage = settings.getLanguage();
        if (!BuiltInLanguages.isBuiltIn(configuredLanguage)) {
            return "custom";
        }
        return configuredLanguage.toLowerCase(Locale.ROOT);
    }

    static String premiumRouting(Settings settings) {
        Settings.PremiumSettings premiumSettings = settings.getPremiumSettings();
        if (!premiumSettings.isCheckEnabled()) {
            return DISABLED_CATEGORY;
        }
        return premiumSettings.isBypassAuthServer()
                ? VERIFIED_BYPASS_CATEGORY
                : AUTH_SERVER_CATEGORY;
    }

    static String floodgateRouting(Settings settings) {
        if (!settings.isFloodgateIntegrationEnabled()) {
            return DISABLED_CATEGORY;
        }
        return settings.isFloodgateBypassAuthServerEnabled()
                ? VERIFIED_BYPASS_CATEGORY
                : AUTH_SERVER_CATEGORY;
    }

    static String twoFactorSupport(Settings settings) {
        Settings.TwoFactorSettings twoFactorSettings = settings.getTwoFactorSettings();
        return twoFactorSettings != null && twoFactorSettings.isEnabled()
                ? ENABLED_CATEGORY
                : DISABLED_CATEGORY;
    }

    private static String clientVersion(Player player) {
        if (player == null) {
            return UNKNOWN_CLIENT_VERSION;
        }
        ProtocolVersion protocolVersion = player.getProtocolVersion();
        if (protocolVersion == null || protocolVersion.isUnknown()) {
            return UNKNOWN_CLIENT_VERSION;
        }
        if (protocolVersion.isLegacy()) {
            return "Legacy";
        }
        String version = protocolVersion.getMostRecentSupportedVersion();
        return version == null || version.isBlank() ? UNKNOWN_CLIENT_VERSION : version;
    }
}
