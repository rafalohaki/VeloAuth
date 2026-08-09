package net.rafalohaki.veloauth.authserver;

import org.slf4j.Logger;

import java.io.IOException;
import java.io.InputStream;
import java.net.http.HttpClient;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.HexFormat;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.locks.ReentrantLock;
import java.util.jar.JarFile;

/** Downloads and verifies the separately licensed embedded protocol runtime. */
final class RuntimeArtifactManager {

    private static final long MAXIMUM_ARTIFACT_BYTES = 32L * 1024 * 1024;
    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(30);
    private static final Set<String> REQUIRED_ENTRIES = Set.of(
            "com/viaversion/viaversion/ViaManagerImpl.class",
            "com/viaversion/viaversion/platform/ViaChannelInitializer.class",
            "com/viaversion/viaversion/protocols/v1_8to1_9/Protocol1_8To1_9.class");
    private static final ReentrantLock PUBLICATION_LOCK = new ReentrantLock();

    private final Path runtimeDirectory;
    private final RuntimeArtifactDescriptor artifact;
    private final HttpClient httpClient;
    private final Logger logger;
    private final boolean requireHttps;

    RuntimeArtifactManager(
            Path runtimeDirectory,
            RuntimeArtifactDescriptor artifact,
            HttpClient httpClient,
            Logger logger,
            boolean requireHttps) {
        this.runtimeDirectory = Objects.requireNonNull(runtimeDirectory, "runtimeDirectory")
                .toAbsolutePath().normalize();
        this.artifact = Objects.requireNonNull(artifact, "artifact");
        this.httpClient = Objects.requireNonNull(httpClient, "httpClient");
        this.logger = Objects.requireNonNull(logger, "logger");
        this.requireHttps = requireHttps;
    }

    Path resolve() {
        PUBLICATION_LOCK.lock();
        try {
            validateTransport();
            Files.createDirectories(runtimeDirectory);
            Path target = runtimeDirectory.resolve(artifact.artifactName());
            rejectSymbolicLink(target);
            if (isValidArtifact(target)) {
                return target;
            }
            if (Files.exists(target, LinkOption.NOFOLLOW_LINKS)) {
                logger.warn("Cached embedded protocol runtime failed verification; replacing {}", target);
            }
            return downloadAndPublish(target);
        } catch (IOException e) {
            throw new IllegalStateException("Unable to prepare embedded protocol runtime", e);
        } finally {
            PUBLICATION_LOCK.unlock();
        }
    }

    private Path downloadAndPublish(Path target) throws IOException {
        logger.info("Downloading verified embedded protocol runtime {} from {}",
                artifact.artifactName(), artifact.uri().getHost());
        Path temporary = Files.createTempFile(runtimeDirectory, ".viaversion-", ".download");
        try {
            HttpResponse<InputStream> response = RuntimeIo.send(
                    httpClient,
                    RuntimeIo.request(artifact.uri(), REQUEST_TIMEOUT,
                            "application/java-archive, application/octet-stream"),
                    "Interrupted while downloading embedded protocol runtime");
            try (InputStream body = response.body()) {
                if (response.statusCode() != 200) {
                    throw new IOException("Protocol runtime repository returned HTTP " + response.statusCode());
                }
                long declaredLength = response.headers().firstValueAsLong("Content-Length").orElse(-1);
                if (declaredLength > MAXIMUM_ARTIFACT_BYTES) {
                    throw new IOException("Protocol runtime exceeds the maximum allowed size");
                }
                copyBounded(body, temporary);
            }

            RuntimeIo.applyOwnerOnlyPermissions(temporary);
            if (!isValidArtifact(temporary)) {
                throw new IOException("Downloaded protocol runtime failed checksum or structure validation");
            }
            RuntimeIo.publishAtomically(temporary, target);
            if (!isValidArtifact(target)) {
                throw new IOException("Published protocol runtime failed post-move validation");
            }
            logger.info("Embedded protocol runtime {} verified and cached", artifact.artifactName());
            return target;
        } finally {
            Files.deleteIfExists(temporary);
        }
    }

    private static void copyBounded(InputStream input, Path target) throws IOException {
        byte[] buffer = new byte[16 * 1024];
        long total = 0;
        try (var output = Files.newOutputStream(target,
                StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING)) {
            int read;
            while ((read = input.read(buffer)) != -1) {
                total += read;
                if (total > MAXIMUM_ARTIFACT_BYTES) {
                    throw new IOException("Protocol runtime exceeds the maximum allowed size");
                }
                output.write(buffer, 0, read);
            }
        }
    }

    private boolean isValidArtifact(Path artifact) {
        if (!Files.isRegularFile(artifact, LinkOption.NOFOLLOW_LINKS)) {
            return false;
        }
        try {
            if (Files.size(artifact) <= 0 || Files.size(artifact) > MAXIMUM_ARTIFACT_BYTES
                    || !this.artifact.sha256().equals(sha256(artifact))) {
                return false;
            }
            try (JarFile jar = new JarFile(artifact.toFile(), true)) {
                return REQUIRED_ENTRIES.stream().allMatch(entry -> jar.getJarEntry(entry) != null);
            }
        } catch (IOException e) {
            return false;
        }
    }

    private void validateTransport() {
        if (requireHttps && !"https".equalsIgnoreCase(artifact.uri().getScheme())) {
            throw new IllegalStateException("Embedded protocol runtime must be downloaded over HTTPS");
        }
    }

    private static void rejectSymbolicLink(Path target) {
        if (Files.isSymbolicLink(target)) {
            throw new IllegalStateException("Refusing symbolic-link protocol runtime cache: " + target);
        }
    }

    private static String sha256(Path path) throws IOException {
        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 is unavailable", impossible);
        }
        try (InputStream input = Files.newInputStream(path)) {
            byte[] buffer = new byte[16 * 1024];
            int read;
            while ((read = input.read(buffer)) != -1) {
                digest.update(buffer, 0, read);
            }
        }
        return HexFormat.of().formatHex(digest.digest());
    }

}
