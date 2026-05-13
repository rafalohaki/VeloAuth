package net.rafalohaki.veloauth.util;

import com.velocitypowered.api.command.CommandSource;
import com.velocitypowered.api.proxy.Player;
import net.kyori.adventure.text.Component;
import net.rafalohaki.veloauth.database.DatabaseManager.DbResult;
import net.rafalohaki.veloauth.i18n.Messages;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.slf4j.Logger;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;

/**
 * Unit tests for {@link DatabaseErrorHandler}.
 * <p>
 * Verifies the contract:
 * <ul>
 *   <li>{@code isDatabaseError() == false} → returns {@code false}, no logging, no player message.</li>
 *   <li>{@code isDatabaseError() == true} → returns {@code true}, logs with SECURITY marker,
 *       sends localized error component to the player/source.</li>
 *   <li>Custom error key is honored by {@code handleErrorWithKey}.</li>
 * </ul>
 */
@ExtendWith(MockitoExtension.class)
class DatabaseErrorHandlerTest {

    @Mock
    private Player player;

    @Mock
    private CommandSource commandSource;

    @Mock
    private Logger logger;

    @Mock
    private Messages messages;

    private static final String OPERATION = "Test operation";
    private static final String DEFAULT_ERROR_KEY = "error.database.query";
    private static final String CUSTOM_ERROR_KEY = "error.database.custom";

    private static DbResult<Object> successResult() {
        return DbResult.success("ok");
    }

    private static DbResult<Object> errorResult() {
        return DbResult.databaseError("connection refused");
    }

    // ===== handleError(DbResult, Player, ...) =====

    @Test
    void handleErrorPlayer_successResult_returnsFalseAndDoesNotInteract() {
        boolean handled = DatabaseErrorHandler.handleError(
                successResult(), player, OPERATION, logger, messages);

        assertFalse(handled);
        verify(player, never()).sendMessage(any(Component.class));
        verify(logger, never()).error(any(org.slf4j.Marker.class), any(String.class), any(), any(), any());
        verify(messages, never()).get(any());
    }

    @Test
    void handleErrorPlayer_errorResult_logsAndSendsLocalizedError() {
        when(logger.isErrorEnabled()).thenReturn(true);
        when(player.getUsername()).thenReturn("alice");
        when(messages.get(DEFAULT_ERROR_KEY)).thenReturn("Database error, please try again.");

        boolean handled = DatabaseErrorHandler.handleError(
                errorResult(), player, OPERATION, logger, messages);

        assertTrue(handled);
        verify(messages).get(DEFAULT_ERROR_KEY);
        verify(player).sendMessage(any(Component.class));
    }

    @Test
    void handleErrorPlayer_errorResult_logIncludesOperationAndIdentifier() {
        when(logger.isErrorEnabled()).thenReturn(true);
        when(player.getUsername()).thenReturn("alice");
        when(messages.get(DEFAULT_ERROR_KEY)).thenReturn("err");

        DatabaseErrorHandler.handleError(errorResult(), player, OPERATION, logger, messages);

        ArgumentCaptor<String> opCaptor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> idCaptor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> msgCaptor = ArgumentCaptor.forClass(String.class);
        verify(logger).error(any(org.slf4j.Marker.class),
                eq("[DATABASE ERROR] {} failed for {}: {}"),
                opCaptor.capture(), idCaptor.capture(), msgCaptor.capture());
        assertTrue(opCaptor.getValue().equals(OPERATION));
        assertTrue(idCaptor.getValue().equals("alice"));
        assertTrue(msgCaptor.getValue().contains("connection refused"));
    }

    // ===== handleError(DbResult, CommandSource, ...) =====

    @Test
    void handleErrorCommandSource_successResult_returnsFalseAndDoesNotInteract() {
        boolean handled = DatabaseErrorHandler.handleError(
                successResult(), commandSource, "alice", OPERATION, logger, messages);

        assertFalse(handled);
        verify(commandSource, never()).sendMessage(any(Component.class));
        verify(messages, never()).get(any());
    }

    @Test
    void handleErrorCommandSource_errorResult_logsAndSendsLocalizedError() {
        when(logger.isErrorEnabled()).thenReturn(true);
        when(messages.get(DEFAULT_ERROR_KEY)).thenReturn("Database error");

        boolean handled = DatabaseErrorHandler.handleError(
                errorResult(), commandSource, "alice", OPERATION, logger, messages);

        assertTrue(handled);
        verify(messages).get(DEFAULT_ERROR_KEY);
        verify(commandSource).sendMessage(any(Component.class));
    }

    // ===== handleErrorWithKey =====

    @Test
    void handleErrorWithKey_successResult_returnsFalseAndDoesNotInteract() {
        boolean handled = DatabaseErrorHandler.handleErrorWithKey(
                successResult(), player, OPERATION, logger, messages, CUSTOM_ERROR_KEY);

        assertFalse(handled);
        verify(player, never()).sendMessage(any(Component.class));
        verify(messages, never()).get(any());
    }

    @Test
    void handleErrorWithKey_errorResult_usesCustomKeyNotDefault() {
        when(logger.isErrorEnabled()).thenReturn(true);
        when(player.getUsername()).thenReturn("alice");
        when(messages.get(CUSTOM_ERROR_KEY)).thenReturn("Custom error");

        boolean handled = DatabaseErrorHandler.handleErrorWithKey(
                errorResult(), player, OPERATION, logger, messages, CUSTOM_ERROR_KEY);

        assertTrue(handled);
        verify(messages).get(CUSTOM_ERROR_KEY);
        verify(messages, never()).get(DEFAULT_ERROR_KEY);
        verify(player).sendMessage(any(Component.class));
    }

    @Test
    void handleErrorWithKey_loggerErrorDisabled_doesNotLogButStillSends() {
        when(logger.isErrorEnabled()).thenReturn(false);
        when(player.getUsername()).thenReturn("alice");
        when(messages.get(CUSTOM_ERROR_KEY)).thenReturn("Custom error");

        boolean handled = DatabaseErrorHandler.handleErrorWithKey(
                errorResult(), player, OPERATION, logger, messages, CUSTOM_ERROR_KEY);

        assertTrue(handled);
        // Still sends localized message even when logger is silenced
        verify(player).sendMessage(any(Component.class));
        verify(logger, never()).error(any(org.slf4j.Marker.class), any(String.class), any(), any(), any());
    }
}
