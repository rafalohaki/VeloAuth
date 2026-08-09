package net.rafalohaki.veloauth.authserver;

import net.rafalohaki.veloauth.BuildConstants;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.Duration;
import java.util.Set;

/** Shared bounded-runtime I/O primitives with one transport and publication policy. */
final class RuntimeIo {

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

    static void publishAtomically(Path source, Path target) throws IOException {
        try {
            Files.move(source, target,
                    StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        } catch (AtomicMoveNotSupportedException e) {
            Files.move(source, target, StandardCopyOption.REPLACE_EXISTING);
        }
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
}
