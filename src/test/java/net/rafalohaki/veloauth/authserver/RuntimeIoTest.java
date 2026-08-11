package net.rafalohaki.veloauth.authserver;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.slf4j.Logger;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

class RuntimeIoTest {

    private static final String LIMIT_MESSAGE = "test input exceeds its limit";

    @TempDir
    private Path temporaryDirectory;

    @Test
    void readBounded_ExactLimit_ShouldReturnAllBytes() throws Exception {
        byte[] expected = {1, 2, 3, 4};

        byte[] actual = RuntimeIo.readBounded(
                new ByteArrayInputStream(expected), expected.length, LIMIT_MESSAGE);

        assertArrayEquals(expected, actual);
    }

    @Test
    void readBounded_ExceededLimit_ShouldFailClosed() {
        IOException failure = assertThrows(IOException.class, () -> RuntimeIo.readBounded(
                new ByteArrayInputStream(new byte[]{1, 2, 3, 4}), 3, LIMIT_MESSAGE));

        assertEquals(LIMIT_MESSAGE, failure.getMessage());
    }

    @Test
    void copyBounded_ExactLimit_ShouldWriteAllBytes() throws Exception {
        byte[] expected = {1, 2, 3, 4};
        Path target = temporaryDirectory.resolve("bounded.bin");

        RuntimeIo.copyBounded(
                new ByteArrayInputStream(expected), target, expected.length, LIMIT_MESSAGE);

        assertArrayEquals(expected, Files.readAllBytes(target));
    }

    @Test
    void copyBounded_ExceededLimit_ShouldFailClosed() {
        Path target = temporaryDirectory.resolve("oversized.bin");

        IOException failure = assertThrows(IOException.class, () -> RuntimeIo.copyBounded(
                new ByteArrayInputStream(new byte[]{1, 2, 3, 4}), target, 3, LIMIT_MESSAGE));

        assertEquals(LIMIT_MESSAGE, failure.getMessage());
    }

    @Test
    void closeSafely_CloseFailures_ShouldBeContainedAndLogged() throws Exception {
        Logger logger = mock(Logger.class);
        IOException checkedFailure = new IOException("checked close failure");
        LinkageError linkageFailure = new LinkageError("runtime close failure");
        AutoCloseable checkedResource = () -> {
            throw checkedFailure;
        };
        AutoCloseable linkageResource = () -> {
            throw linkageFailure;
        };

        assertDoesNotThrow(() -> RuntimeIo.closeSafely(checkedResource, logger, "checked resource"));
        assertDoesNotThrow(() -> RuntimeIo.closeSafely(linkageResource, logger, "linked resource"));
        assertDoesNotThrow(() -> RuntimeIo.closeSafely(null, logger, "absent resource"));

        verify(logger).warn("Failed to close {}", "checked resource", checkedFailure);
        verify(logger).warn("Failed to close {}", "linked resource", linkageFailure);
    }
}
