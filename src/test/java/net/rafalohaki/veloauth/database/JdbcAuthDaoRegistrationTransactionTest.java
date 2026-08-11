package net.rafalohaki.veloauth.database;

import net.rafalohaki.veloauth.model.RegisteredPlayer;
import org.junit.jupiter.api.Test;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.startsWith;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S2068")
class JdbcAuthDaoRegistrationTransactionTest {

    private static final String OFFLINE_HASH =
            "$2a$10$offlinehashvalueofflinehashvalueofflinehashval";
    private static final long LATCH_TIMEOUT_SECONDS = 5L;

    @Test
    void insertPlayerIfAbsent_TimeoutWinsBeforeCommit_RollsBackAndReturnsCancelled()
            throws Exception {
        ControlledJdbc controlled = controlledJdbc();
        CountDownLatch insertEntered = new CountDownLatch(1);
        CountDownLatch releaseInsert = new CountDownLatch(1);
        doAnswer(ignored -> {
            insertEntered.countDown();
            assertTrue(releaseInsert.await(LATCH_TIMEOUT_SECONDS, TimeUnit.SECONDS));
            return 1;
        }).when(controlled.statement()).executeUpdate();
        DatabaseManager.RegistrationCommitPermit permit =
                new DatabaseManager.RegistrationCommitPermit();

        try (ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor()) {
            Future<DatabaseManager.RegistrationResult> result = executor.submit(
                    () -> controlled.dao().insertPlayerIfAbsent(player("CancelledAlice"), permit));

            assertTrue(insertEntered.await(LATCH_TIMEOUT_SECONDS, TimeUnit.SECONDS));
            assertEquals(
                    DatabaseManager.RegistrationTimeoutDisposition.CANCELLED_BEFORE_COMMIT,
                    permit.onTimeout());
            releaseInsert.countDown();

            assertEquals(DatabaseManager.RegistrationResult.CANCELLED,
                    result.get(LATCH_TIMEOUT_SECONDS, TimeUnit.SECONDS));
        }

        verify(controlled.connection()).setAutoCommit(false);
        verify(controlled.connection()).rollback();
        verify(controlled.connection(), never()).commit();
    }

    @Test
    void insertPlayerIfAbsent_CommitWinsBeforeTimeout_CommitsAndReturnsCreated()
            throws Exception {
        ControlledJdbc controlled = controlledJdbc();
        CountDownLatch commitEntered = new CountDownLatch(1);
        CountDownLatch releaseCommit = new CountDownLatch(1);
        when(controlled.statement().executeUpdate()).thenReturn(1);
        doAnswer(ignored -> {
            commitEntered.countDown();
            assertTrue(releaseCommit.await(LATCH_TIMEOUT_SECONDS, TimeUnit.SECONDS));
            return null;
        }).when(controlled.connection()).commit();
        DatabaseManager.RegistrationCommitPermit permit =
                new DatabaseManager.RegistrationCommitPermit();

        try (ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor()) {
            Future<DatabaseManager.RegistrationResult> result = executor.submit(
                    () -> controlled.dao().insertPlayerIfAbsent(player("CommittedAlice"), permit));

            assertTrue(commitEntered.await(LATCH_TIMEOUT_SECONDS, TimeUnit.SECONDS));
            assertEquals(
                    DatabaseManager.RegistrationTimeoutDisposition.COMMIT_IN_PROGRESS,
                    permit.onTimeout());
            releaseCommit.countDown();

            assertEquals(DatabaseManager.RegistrationResult.CREATED,
                    result.get(LATCH_TIMEOUT_SECONDS, TimeUnit.SECONDS));
        }

        verify(controlled.connection()).setAutoCommit(false);
        verify(controlled.connection()).commit();
        verify(controlled.connection(), never()).rollback();
        assertFalse(permit.isCancelled());
    }

    @Test
    void insertPlayerIfAbsent_Duplicate_RollsBackBeforeReturningDuplicate() throws Exception {
        ControlledJdbc controlled = controlledJdbc();
        when(controlled.statement().executeUpdate())
                .thenThrow(new SQLException("duplicate key", "23505"));
        DatabaseManager.RegistrationCommitPermit permit =
                new DatabaseManager.RegistrationCommitPermit();

        DatabaseManager.RegistrationResult result = controlled.dao()
                .insertPlayerIfAbsent(player("DuplicateAlice"), permit);

        assertEquals(DatabaseManager.RegistrationResult.DUPLICATE, result);
        var order = inOrder(controlled.connection(), controlled.statement());
        order.verify(controlled.connection()).setAutoCommit(false);
        order.verify(controlled.statement()).executeUpdate();
        order.verify(controlled.connection()).rollback();
        verify(controlled.connection(), never()).commit();
    }

    @Test
    void insertPlayerIfAbsent_CommitThrows_ReturnsCommitUnknownWithoutFalseSuccess()
            throws Exception {
        ControlledJdbc controlled = controlledJdbc();
        when(controlled.statement().executeUpdate()).thenReturn(1);
        doAnswer(ignored -> {
            throw new SQLException("connection lost while committing", "08006");
        }).when(controlled.connection()).commit();
        DatabaseManager.RegistrationCommitPermit permit =
                new DatabaseManager.RegistrationCommitPermit();

        DatabaseManager.RegistrationResult result = controlled.dao()
                .insertPlayerIfAbsent(player("UnknownAlice"), permit);

        assertEquals(DatabaseManager.RegistrationResult.COMMIT_UNKNOWN, result);
        verify(controlled.connection()).rollback();
        assertEquals(DatabaseManager.RegistrationTimeoutDisposition.COMMIT_UNKNOWN,
                permit.onTimeout());
    }

    private ControlledJdbc controlledJdbc() throws SQLException {
        DatabaseConfig config = mock(DatabaseConfig.class);
        DataSource dataSource = mock(DataSource.class);
        Connection connection = mock(Connection.class);
        PreparedStatement statement = mock(PreparedStatement.class);
        when(config.getStorageType()).thenReturn("POSTGRESQL");
        when(config.getDataSource()).thenReturn(dataSource);
        when(dataSource.getConnection()).thenReturn(connection);
        when(connection.getAutoCommit()).thenReturn(true);
        when(connection.prepareStatement(startsWith("INSERT"))).thenReturn(statement);
        return new ControlledJdbc(new JdbcAuthDao(config), connection, statement);
    }

    private RegisteredPlayer player(String nickname) {
        return new RegisteredPlayer(
                nickname, OFFLINE_HASH, "127.0.0.1", UUID.randomUUID().toString());
    }

    private record ControlledJdbc(
            JdbcAuthDao dao, Connection connection, PreparedStatement statement) { }
}
