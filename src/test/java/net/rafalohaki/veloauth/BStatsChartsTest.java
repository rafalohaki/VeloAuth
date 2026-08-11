package net.rafalohaki.veloauth;

import com.velocitypowered.api.network.ProtocolVersion;
import com.velocitypowered.api.proxy.Player;
import net.rafalohaki.veloauth.config.Settings;
import org.bstats.charts.CustomChart;
import org.bstats.velocity.Metrics;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class BStatsChartsTest {

    @Test
    void clientVersionCounts_MultiplePlayers_AggregatesOnlyProtocolVersions() {
        Player firstMinecraft18Player = playerUsing(ProtocolVersion.MINECRAFT_1_8);
        Player secondMinecraft18Player = playerUsing(ProtocolVersion.MINECRAFT_1_8);
        Player minecraft262Player = playerUsing(ProtocolVersion.MINECRAFT_26_2);

        Map<String, Integer> result = BStatsCharts.clientVersionCounts(List.of(
                firstMinecraft18Player, secondMinecraft18Player, minecraft262Player));

        assertEquals(Map.of(
                ProtocolVersion.MINECRAFT_1_8.getMostRecentSupportedVersion(), 2,
                ProtocolVersion.MINECRAFT_26_2.getMostRecentSupportedVersion(), 1), result);
        verifyNoPlayerIdentityWasRead(firstMinecraft18Player);
        verifyNoPlayerIdentityWasRead(secondMinecraft18Player);
        verifyNoPlayerIdentityWasRead(minecraft262Player);
    }

    @Test
    void clientVersionCounts_UnknownProtocol_UsesBoundedFallbackCategory() {
        Player player = playerUsing(null);

        assertEquals(Map.of(BStatsCharts.UNKNOWN_CLIENT_VERSION, 1),
                BStatsCharts.clientVersionCounts(List.of(player)));
    }

    @Test
    void register_ValidDependencies_AddsStablePrivacySafeChartSet() {
        Metrics metrics = mock(Metrics.class);
        com.velocitypowered.api.proxy.ProxyServer proxyServer =
                mock(com.velocitypowered.api.proxy.ProxyServer.class);
        Settings settings = mock(Settings.class);
        Settings.TwoFactorSettings twoFactorSettings = mock(Settings.TwoFactorSettings.class);
        when(proxyServer.getAllPlayers()).thenReturn(List.of());
        when(settings.getAuthServerMode()).thenReturn(Settings.AuthServerMode.EMBEDDED);
        when(settings.getDatabaseStorageType()).thenReturn("POSTGRESQL");
        when(settings.getLanguage()).thenReturn("pl");
        when(settings.isPremiumCheckEnabled()).thenReturn(true);
        when(settings.isFloodgateIntegrationEnabled()).thenReturn(true);
        when(settings.isFloodgateBypassAuthServerEnabled()).thenReturn(true);
        when(settings.getTwoFactorSettings()).thenReturn(twoFactorSettings);
        when(twoFactorSettings.isEnabled()).thenReturn(true);

        BStatsCharts.register(metrics, proxyServer, settings);

        ArgumentCaptor<CustomChart> chartCaptor = ArgumentCaptor.forClass(CustomChart.class);
        verify(metrics, times(BStatsCharts.CHART_COUNT)).addCustomChart(chartCaptor.capture());
        assertEquals(BStatsCharts.CHART_COUNT, chartCaptor.getAllValues().size());
        assertInstanceOf(org.bstats.charts.AdvancedPie.class, chartCaptor.getAllValues().getFirst());
    }

    @Test
    void categoryHelpers_CustomOrInvalidValues_NeverExposeFreeText() {
        Settings settings = mock(Settings.class);
        Settings.TwoFactorSettings twoFactorSettings = mock(Settings.TwoFactorSettings.class);
        when(settings.getLanguage()).thenReturn("private-network-name");
        when(settings.getDatabaseStorageType()).thenReturn("private-database-name");
        when(settings.isPremiumCheckEnabled()).thenReturn(false);
        when(settings.getPremiumSettings()).thenReturn(premiumSettings(false, false));
        when(settings.isFloodgateIntegrationEnabled()).thenReturn(false);
        when(settings.getTwoFactorSettings()).thenReturn(twoFactorSettings);

        assertEquals("custom", BStatsCharts.language(settings));
        assertEquals("OTHER", BStatsCharts.databaseBackend(settings));
        assertEquals("disabled", BStatsCharts.premiumRouting(settings));
        assertEquals("disabled", BStatsCharts.floodgateRouting(settings));
        assertEquals("disabled", BStatsCharts.twoFactorSupport(settings));
    }

    @Test
    void categoryHelpers_EnabledFeatures_UseOnlyDocumentedCategories() {
        Settings settings = mock(Settings.class);
        Settings.TwoFactorSettings twoFactorSettings = mock(Settings.TwoFactorSettings.class);
        when(settings.getLanguage()).thenReturn("PL");
        when(settings.getDatabaseStorageType()).thenReturn("POSTGRESQL");
        when(settings.isPremiumCheckEnabled()).thenReturn(true);
        when(settings.isPremiumBypassAuthServerEnabled()).thenReturn(true);
        when(settings.getPremiumSettings()).thenReturn(premiumSettings(true, true));
        when(settings.isFloodgateIntegrationEnabled()).thenReturn(true);
        when(settings.isFloodgateBypassAuthServerEnabled()).thenReturn(false);
        when(settings.getTwoFactorSettings()).thenReturn(twoFactorSettings);
        when(twoFactorSettings.isEnabled()).thenReturn(true);

        assertEquals("pl", BStatsCharts.language(settings));
        assertEquals("POSTGRESQL", BStatsCharts.databaseBackend(settings));
        assertEquals("verified-bypass", BStatsCharts.premiumRouting(settings));
        assertEquals("auth-server", BStatsCharts.floodgateRouting(settings));
        assertEquals("enabled", BStatsCharts.twoFactorSupport(settings));
    }

    @Test
    void premiumRouting_ReloadInterleaving_NeverPublishesTornCategory() throws Exception {
        Settings settings = mock(Settings.class);
        Settings.PremiumSettings oldGeneration = premiumSettings(true, false);
        Settings.PremiumSettings newGeneration = premiumSettings(false, true);
        AtomicReference<Settings.PremiumSettings> generation =
                new AtomicReference<>(oldGeneration);
        CountDownLatch snapshotRead = new CountDownLatch(1);
        CountDownLatch releaseRead = new CountDownLatch(1);

        when(settings.isPremiumCheckEnabled()).thenAnswer(ignored -> {
            boolean captured = generation.get().isCheckEnabled();
            snapshotRead.countDown();
            awaitLatch(releaseRead);
            return captured;
        });
        when(settings.isPremiumBypassAuthServerEnabled()).thenAnswer(
                ignored -> generation.get().isBypassAuthServer());
        when(settings.getPremiumSettings()).thenAnswer(ignored -> {
            Settings.PremiumSettings captured = generation.get();
            snapshotRead.countDown();
            awaitLatch(releaseRead);
            return captured;
        });

        ExecutorService executor = Executors.newSingleThreadExecutor();
        try {
            Future<String> category = executor.submit(() -> BStatsCharts.premiumRouting(settings));
            assertTrue(snapshotRead.await(5, TimeUnit.SECONDS),
                    "bStats did not start reading the old settings generation");
            generation.set(newGeneration);
            releaseRead.countDown();

            assertEquals("auth-server", category.get(5, TimeUnit.SECONDS),
                    "Neither complete generation enables verified bypass");
        } finally {
            releaseRead.countDown();
            executor.shutdownNow();
        }
    }

    private static Settings.PremiumSettings premiumSettings(boolean checkEnabled, boolean bypass) {
        return new Settings.PremiumSettings(
                checkEnabled,
                false,
                bypass,
                new Settings.PremiumResolverSettings());
    }

    private static void awaitLatch(CountDownLatch latch) {
        try {
            assertTrue(latch.await(5, TimeUnit.SECONDS), "Timed out waiting for settings interleave");
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new AssertionError("Interrupted while waiting for settings interleave", e);
        }
    }

    private static Player playerUsing(ProtocolVersion protocolVersion) {
        Player player = mock(Player.class);
        when(player.getProtocolVersion()).thenReturn(protocolVersion);
        return player;
    }

    private static void verifyNoPlayerIdentityWasRead(Player player) {
        verify(player, never()).getUsername();
        verify(player, never()).getUniqueId();
        verify(player, never()).getRemoteAddress();
        verify(player, never()).getVirtualHost();
    }
}
