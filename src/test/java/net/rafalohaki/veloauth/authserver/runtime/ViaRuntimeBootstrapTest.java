package net.rafalohaki.veloauth.authserver.runtime;

import io.netty.channel.Channel;
import io.netty.util.concurrent.Future;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class ViaRuntimeBootstrapTest {

    @Test
    void forwardingRequest_FailedWrite_ShouldLogCauseBeforeClosingChannel() throws Exception {
        Channel channel = mock(Channel.class);
        Logger logger = mock(Logger.class);
        Runnable continuation = mock(Runnable.class);
        @SuppressWarnings("unchecked")
        Future<Object> result = mock(Future.class);
        IllegalStateException cause = new IllegalStateException("write failed");
        when(result.isSuccess()).thenReturn(false);
        when(result.cause()).thenReturn(cause);

        invokeCompletionHandler(channel, 7, continuation, logger, result);

        verify(logger).warn(
                "Failed to send Velocity forwarding request {} - closing embedded channel",
                7, cause);
        verify(channel).close();
        verify(continuation, never()).run();
    }

    @Test
    void forwardingRequest_SuccessfulWrite_ShouldContinueLogin() throws Exception {
        Channel channel = mock(Channel.class);
        Logger logger = mock(Logger.class);
        Runnable continuation = mock(Runnable.class);
        @SuppressWarnings("unchecked")
        Future<Object> result = mock(Future.class);
        when(result.isSuccess()).thenReturn(true);

        invokeCompletionHandler(channel, 8, continuation, logger, result);

        verify(continuation).run();
        verify(channel, never()).close();
    }

    private static void invokeCompletionHandler(
            Channel channel, int transactionId, Runnable continuation,
            Logger logger, Future<?> result) throws Exception {
        Method handler;
        try {
            handler = ViaRuntimeBootstrap.class.getDeclaredMethod(
                    "handleForwardingRequestCompletion",
                    Channel.class, int.class, Runnable.class, Logger.class, Future.class);
        } catch (NoSuchMethodException e) {
            throw new AssertionError("Via forwarding completion must be observable", e);
        }
        handler.setAccessible(true);
        assertDoesNotThrow(() -> {
            try {
                handler.invoke(null, channel, transactionId, continuation, logger, result);
            } catch (IllegalAccessException e) {
                throw new AssertionError(e);
            } catch (InvocationTargetException e) {
                throw new AssertionError(e.getCause());
            }
        });
    }
}
