package net.rafalohaki.veloauth.cache;

import com.github.benmanes.caffeine.cache.Cache;
import net.rafalohaki.veloauth.i18n.Messages;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings({"java:S100", "java:S3011"})
class SessionManagerTest {

    private Messages messages;

    @BeforeEach
    void setUp() {
        messages = new Messages();
        messages.setLanguage("en");
    }

    @Test
    void testHasActiveSession_ExpiredSession_ReturnsFalseAndRemovesSession() throws Exception {
        SessionManager sessionManager = new SessionManager(4, 1, messages);
        UUID playerUuid = UUID.randomUUID();

        sessionManager.startSession(playerUuid, "ExpiredPlayer", "127.0.0.1");
        AuthCache.ActiveSession session = getActiveSessions(sessionManager).getIfPresent(playerUuid);
        setLastActivityTime(session, System.currentTimeMillis() - TimeUnit.MINUTES.toMillis(2));

        assertFalse(sessionManager.hasActiveSession(playerUuid, "ExpiredPlayer", "127.0.0.1"));
        assertEquals(0, sessionManager.size());
    }

    @Test
    void testHasActiveSession_ConcurrentEndSession_BlocksUntilValidationCompletes() throws Exception {
        SessionManager sessionManager = new SessionManager(4, 60, messages);
        UUID playerUuid = UUID.randomUUID();
        String nickname = "RacePlayer";
        String ip = "127.0.0.2";
        BlockingActiveSession blockingSession = new BlockingActiveSession(playerUuid, nickname, ip);
        getActiveSessions(sessionManager).put(playerUuid, blockingSession);

        try (var executor = Executors.newVirtualThreadPerTaskExecutor()) {
            Future<Boolean> hasSessionFuture = executor.submit(
                    () -> sessionManager.hasActiveSession(playerUuid, nickname, ip)
            );

            assertTrue(blockingSession.awaitUpdateStarted());

            Future<?> endSessionFuture = executor.submit(() -> {
                sessionManager.endSession(playerUuid);
                return null;
            });

            assertThrows(TimeoutException.class, () -> endSessionFuture.get(200, TimeUnit.MILLISECONDS));

            blockingSession.releaseUpdate();

            assertTrue(hasSessionFuture.get(5, TimeUnit.SECONDS));
            endSessionFuture.get(5, TimeUnit.SECONDS);
        }

        assertFalse(sessionManager.hasActiveSession(playerUuid, nickname, ip));
    }

    @Test
    void testStartSession_ConcurrentStarts_DoesNotExceedMaxSessions() throws Exception {
        int maxSessions = 4;

        for (int iteration = 0; iteration < 10; iteration++) {
            SessionManager sessionManager = new SessionManager(maxSessions, 60, messages);
            int offset = iteration * 32;

            runConcurrently(32, index -> {
                int playerIndex = offset + index;
                UUID playerUuid = UUID.nameUUIDFromBytes(
                        ("session-player-" + playerIndex).getBytes(StandardCharsets.UTF_8)
                );
                sessionManager.startSession(
                        playerUuid,
                        "Player" + playerIndex,
                        "10.0.0." + (playerIndex % 255)
                );
            });

            assertEquals(maxSessions, sessionManager.size());
        }
    }

    @SuppressWarnings("unchecked")
    private static Cache<UUID, AuthCache.ActiveSession> getActiveSessions(SessionManager sessionManager)
            throws Exception {
        Field field = SessionManager.class.getDeclaredField("activeSessions");
        field.setAccessible(true);
        return (Cache<UUID, AuthCache.ActiveSession>) field.get(sessionManager);
    }

    private static void setLastActivityTime(AuthCache.ActiveSession session, long timestamp) throws Exception {
        Field field = AuthCache.ActiveSession.class.getDeclaredField("lastActivityTime");
        field.setAccessible(true);
        field.setLong(session, timestamp);
    }

    private static void runConcurrently(int taskCount, ThrowingIntConsumer action) throws Exception {
        CountDownLatch ready = new CountDownLatch(taskCount);
        CountDownLatch start = new CountDownLatch(1);

        try (var executor = Executors.newVirtualThreadPerTaskExecutor()) {
            List<Future<?>> futures = new ArrayList<>(taskCount);
            for (int index = 0; index < taskCount; index++) {
                int currentIndex = index;
                futures.add(executor.submit(() -> {
                    ready.countDown();
                    assertTrue(start.await(5, TimeUnit.SECONDS));
                    action.accept(currentIndex);
                    return null;
                }));
            }

            assertTrue(ready.await(5, TimeUnit.SECONDS));
            start.countDown();

            for (Future<?> future : futures) {
                future.get(5, TimeUnit.SECONDS);
            }
        }
    }

    @FunctionalInterface
    private interface ThrowingIntConsumer {
        void accept(int index) throws Exception;
    }

    private static final class BlockingActiveSession extends AuthCache.ActiveSession {

        private final CountDownLatch updateStarted = new CountDownLatch(1);
        private final CountDownLatch releaseUpdate = new CountDownLatch(1);

        private BlockingActiveSession(UUID uuid, String nickname, String ip) {
            super(uuid, nickname, ip);
        }

        @Override
        public void updateActivity() {
            updateStarted.countDown();
            await(releaseUpdate);
            super.updateActivity();
        }

        private boolean awaitUpdateStarted() throws InterruptedException {
            return updateStarted.await(5, TimeUnit.SECONDS);
        }

        private void releaseUpdate() {
            releaseUpdate.countDown();
        }

        private static void await(CountDownLatch latch) {
            try {
                if (!latch.await(5, TimeUnit.SECONDS)) {
                    throw new IllegalStateException("Timed out waiting for latch");
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException("Interrupted while waiting for latch", e);
            }
        }
    }
}
