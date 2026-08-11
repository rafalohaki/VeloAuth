package net.rafalohaki.veloauth.authserver;

import net.rafalohaki.veloauth.BuildConstants;
import org.slf4j.Logger;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.time.Duration;
import java.util.Objects;
import java.util.Set;

/** Shared bounded-runtime I/O primitives with one transport and publication policy. */
final class RuntimeIo {

    private static final int BUFFER_BYTES = 16 * 1024;

    private RuntimeIo() {
        // Utility class.
    }

    static HttpRequest request(URI uri, Duration timeout, String accept) {
        return HttpRequest.newBuilder(uri)
                .timeout(timeout)
                .header("Accept", accept)
                .header("User-Agent", "VeloAuth/" + BuildConstants.VERSION)
                .GET()
                .build();
    }

    static HttpResponse<InputStream> send(
            HttpClient client,
            HttpRequest request,
            String interruptedMessage) throws IOException {
        try {
            return client.send(request, HttpResponse.BodyHandlers.ofInputStream());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(interruptedMessage, e);
        }
    }

    static byte[] readBounded(
            InputStream input,
            int maximumBytes,
            String exceededMessage) throws IOException {
        validateMaximum(maximumBytes);
        ByteArrayOutputStream output = new ByteArrayOutputStream(
                Math.min(maximumBytes, BUFFER_BYTES));
        copyBounded(input, output, maximumBytes, exceededMessage);
        return output.toByteArray();
    }

    static void copyBounded(
            InputStream input,
            Path target,
            long maximumBytes,
            String exceededMessage) throws IOException {
        validateMaximum(maximumBytes);
        try (OutputStream output = Files.newOutputStream(
                Objects.requireNonNull(target, "target"),
                StandardOpenOption.CREATE,
                StandardOpenOption.WRITE,
                StandardOpenOption.TRUNCATE_EXISTING)) {
            copyBounded(input, output, maximumBytes, exceededMessage);
        }
    }

    static void closeSafely(AutoCloseable resource, Logger logger, String description) {
        if (resource == null) {
            return;
        }
        try {
            resource.close();
        } catch (Exception | LinkageError exception) {
            Objects.requireNonNull(logger, "logger")
                    .warn("Failed to close {}", description, exception);
        }
    }

    static void publishAtomically(Path source, Path target) throws IOException {
        Files.move(source, target,
                StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
    }

    static void applyOwnerOnlyPermissions(Path path) {
        try {
            Files.setPosixFilePermissions(path, Set.of(
                    java.nio.file.attribute.PosixFilePermission.OWNER_READ,
                    java.nio.file.attribute.PosixFilePermission.OWNER_WRITE));
        } catch (IOException | UnsupportedOperationException ignored) {
            // Windows and non-POSIX filesystems do not expose POSIX permissions.
        }
    }

    private static void copyBounded(
            InputStream input,
            OutputStream output,
            long maximumBytes,
            String exceededMessage) throws IOException {
        Objects.requireNonNull(input, "input");
        Objects.requireNonNull(output, "output");
        Objects.requireNonNull(exceededMessage, "exceededMessage");
        byte[] buffer = new byte[BUFFER_BYTES];
        long total = 0;
        int read;
        while ((read = input.read(buffer)) != -1) {
            if (read == 0) {
                continue;
            }
            if (read > maximumBytes - total) {
                throw new IOException(exceededMessage);
            }
            output.write(buffer, 0, read);
            total += read;
        }
    }

    private static void validateMaximum(long maximumBytes) {
        if (maximumBytes < 0) {
            throw new IllegalArgumentException("maximumBytes must not be negative");
        }
    }
}
