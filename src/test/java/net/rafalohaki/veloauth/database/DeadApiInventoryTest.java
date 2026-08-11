package net.rafalohaki.veloauth.database;

import net.rafalohaki.veloauth.i18n.Messages;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertFalse;

class DeadApiInventoryTest {

    @Test
    void productionGateways_ObsoleteApi_ShouldStayRemoved() {
        assertNoDeclaredMethods(Messages.class,
                "getLanguageDisplayName", "getLanguageNativeName");
        assertNoDeclaredMethods(DatabaseManager.class,
                "isHealthy", "getLastHealthCheckTime", "wasLastHealthCheckPassed",
                "getAllPlayers", "removeCachedPlayer");
        assertNoDeclaredMethods(DatabaseManager.DbResult.class, "getValueOptional");
        assertNoDeclaredMethods(DatabaseHealthCheck.class,
                "isHealthy", "getLastHealthCheckTime", "wasLastHealthCheckPassed");
        assertNoPublicMethods(DatabaseConfig.class,
                "getHostname", "getPort", "getDatabase", "getConnectionPoolSize",
                "isLocalDatabase", "isRemoteDatabase", "getDefaultPort");
    }

    private static void assertNoDeclaredMethods(Class<?> type, String... obsoleteNames) {
        Set<String> declared = Arrays.stream(type.getDeclaredMethods())
                .map(Method::getName)
                .collect(Collectors.toSet());
        for (String obsoleteName : obsoleteNames) {
            assertFalse(declared.contains(obsoleteName),
                    () -> type.getSimpleName() + '.' + obsoleteName + " remains declared");
        }
    }

    private static void assertNoPublicMethods(Class<?> type, String... obsoleteNames) {
        Set<String> publicMethods = Arrays.stream(type.getDeclaredMethods())
                .filter(method -> Modifier.isPublic(method.getModifiers()))
                .map(Method::getName)
                .collect(Collectors.toSet());
        for (String obsoleteName : obsoleteNames) {
            assertFalse(publicMethods.contains(obsoleteName),
                    () -> type.getSimpleName() + '.' + obsoleteName + " remains public");
        }
    }
}
