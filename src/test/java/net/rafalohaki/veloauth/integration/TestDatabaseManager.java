package net.rafalohaki.veloauth.integration;

import net.rafalohaki.veloauth.database.DatabaseConfig;
import net.rafalohaki.veloauth.database.DatabaseManager;
import net.rafalohaki.veloauth.database.DatabaseManager.DbResult;
import net.rafalohaki.veloauth.i18n.Messages;
import net.rafalohaki.veloauth.model.RegisteredPlayer;

import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Test stub for DatabaseManager to avoid Mockito inline mocking issues on Java 21.
 * Provides controllable results for initialize() and findPlayerByNickname().
 */
class TestDatabaseManager extends DatabaseManager {

    private CompletableFuture<Boolean> initResult = CompletableFuture.completedFuture(true);
    private final Map<String, CompletableFuture<DbResult<RegisteredPlayer>>> findResults = new ConcurrentHashMap<>();
    private final Map<String, CompletableFuture<DbResult<Boolean>>> premiumResults = new ConcurrentHashMap<>();

    TestDatabaseManager(DatabaseConfig config, Messages messages) {
        super(config, messages);
    }

    @Override
    public CompletableFuture<Boolean> initialize() {
        return initResult;
    }

    void setInitResult(CompletableFuture<Boolean> initResult) {
        this.initResult = initResult != null ? initResult : CompletableFuture.completedFuture(true);
    }

    void setFindResult(String nickname, CompletableFuture<DbResult<RegisteredPlayer>> result) {
        if (nickname != null && result != null) {
            findResults.put(nickname.toLowerCase(), result);
        }
    }

    void setPremiumResult(String username, CompletableFuture<DbResult<Boolean>> result) {
        if (username != null && result != null) {
            premiumResults.put(username, result);
        }
    }

    @Override
    public CompletableFuture<DbResult<RegisteredPlayer>> findPlayerByNickname(String nickname) {
        if (nickname == null || nickname.isEmpty()) {
            return CompletableFuture.completedFuture(DbResult.success(null));
        }
        return findResults.getOrDefault(nickname.toLowerCase(), CompletableFuture.completedFuture(DbResult.success(null)));
    }

    @Override
    public CompletableFuture<DbResult<Boolean>> isPremium(String username) {
        if (username == null || username.isEmpty()) {
            return CompletableFuture.completedFuture(DbResult.success(false));
        }
        return premiumResults.getOrDefault(username, CompletableFuture.completedFuture(DbResult.success(false)));
    }
}