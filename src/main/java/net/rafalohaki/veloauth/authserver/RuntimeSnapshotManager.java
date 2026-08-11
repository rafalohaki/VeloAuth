package net.rafalohaki.veloauth.authserver;

import org.slf4j.Logger;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.locks.ReentrantLock;

/** Stages an exact maintainer-reviewed ViaVersion runtime for activation on a later restart. */
final class RuntimeSnapshotManager {

    static final String ACTIVE_MANIFEST = "active-runtime.properties";
    static final String PENDING_MANIFEST = "pending-runtime.properties";
    static final String REVIEWED_TRUST = "veloauth-reviewed-v1";

    private static final int MAXIMUM_MANIFEST_BYTES = 4096;
    private static final ReentrantLock STORE_LOCK = new ReentrantLock();

    private final Path runtimeDirectory;
    private final ViaVersionRepositoryClient repositoryClient;
    private final Logger logger;

    RuntimeSnapshotManager(Path dataDirectory, Logger logger) {
        this(dataDirectory.resolve("runtime"), ViaVersionRepositoryClient.official(), logger);
    }

    RuntimeSnapshotManager(
            Path runtimeDirectory,
            URI repository,
            HttpClient httpClient,
            Logger logger,
            boolean requireHttps) {
        this(runtimeDirectory,
                ViaVersionRepositoryClient.create(repository, httpClient, requireHttps),
                logger);
    }

    private RuntimeSnapshotManager(
            Path runtimeDirectory,
            ViaVersionRepositoryClient repositoryClient,
            Logger logger) {
        this.runtimeDirectory = Objects.requireNonNull(runtimeDirectory, "runtimeDirectory")
                .toAbsolutePath().normalize();
        this.repositoryClient = Objects.requireNonNull(repositoryClient, "repositoryClient");
        this.logger = Objects.requireNonNull(logger, "logger");
    }

    List<RuntimeCandidate> startupCandidates() {
        STORE_LOCK.lock();
        try {
            Files.createDirectories(runtimeDirectory);
            Map<RuntimeArtifactDescriptor, RuntimeCandidate> candidates = new LinkedHashMap<>();
            addManifestCandidate(candidates, PENDING_MANIFEST, CandidateSource.PENDING);
            addManifestCandidate(candidates, ACTIVE_MANIFEST, CandidateSource.ACTIVE);
            RuntimeArtifactDescriptor pinned = RuntimeArtifactDescriptor.pinned();
            candidates.putIfAbsent(pinned, new RuntimeCandidate(pinned, CandidateSource.PINNED));
            return List.copyOf(candidates.values());
        } catch (IOException e) {
            throw new IllegalStateException("Unable to inspect embedded protocol runtime state", e);
        } finally {
            STORE_LOCK.unlock();
        }
    }

    Path resolve(RuntimeCandidate candidate) {
        Objects.requireNonNull(candidate, "candidate");
        return repositoryClient.resolveArtifact(runtimeDirectory, candidate.artifact(), logger);
    }

    void recordSuccessful(RuntimeCandidate candidate) {
        if (candidate.source() != CandidateSource.PENDING) {
            return;
        }
        STORE_LOCK.lock();
        try {
            Files.deleteIfExists(runtimeDirectory.resolve(PENDING_MANIFEST));
            writeManifest(ACTIVE_MANIFEST, candidate.artifact());
            pruneArtifacts(Set.of(
                    candidate.artifact().artifactName(),
                    RuntimeArtifactDescriptor.pinned().artifactName()));
            logger.info("Activated reviewed ViaVersion runtime {} after successful restart validation",
                    candidate.artifact().version());
        } catch (IOException e) {
            throw new IllegalStateException("Unable to activate reviewed embedded protocol runtime", e);
        } finally {
            STORE_LOCK.unlock();
        }
    }

    void recordFailed(RuntimeCandidate candidate, Throwable failure) {
        if (candidate.source() == CandidateSource.PINNED) {
            return;
        }
        STORE_LOCK.lock();
        try {
            String manifest = candidate.source() == CandidateSource.PENDING
                    ? PENDING_MANIFEST : ACTIVE_MANIFEST;
            Files.deleteIfExists(runtimeDirectory.resolve(manifest));
            logger.warn("Rejected {} ViaVersion runtime {}; falling back to the next verified candidate",
                    candidate.source().displayName(), candidate.artifact().version(), failure);
        } catch (IOException e) {
            failure.addSuppressed(e);
            logger.warn("Unable to discard failed ViaVersion runtime manifest", e);
        } finally {
            STORE_LOCK.unlock();
        }
    }

    UpdateResult stageReviewedRuntime(String currentRuntimeVersion) {
        return stageReviewedRuntime(currentRuntimeVersion, RuntimeArtifactDescriptor.reviewed());
    }

    UpdateResult stageReviewedRuntime(
            String currentRuntimeVersion,
            RuntimeArtifactDescriptor candidate) {
        Objects.requireNonNull(currentRuntimeVersion, "currentRuntimeVersion");
        Objects.requireNonNull(candidate, "candidate");
        STORE_LOCK.lock();
        try {
            repositoryClient.validateArtifactTransport(candidate.uri());
            if (!RuntimeArtifactDescriptor.isNewerVersion(
                    candidate.version(), currentRuntimeVersion)
                    || manifestHasArtifact(PENDING_MANIFEST, candidate)
                    || manifestHasArtifact(ACTIVE_MANIFEST, candidate)) {
                return UpdateResult.CURRENT;
            }

            Files.createDirectories(runtimeDirectory);
            resolve(new RuntimeCandidate(candidate, CandidateSource.PENDING));
            writeManifest(PENDING_MANIFEST, candidate);
            pruneArtifacts(artifactsToKeep(candidate));
            logger.info("Staged maintainer-reviewed ViaVersion runtime {} for the next proxy restart",
                    candidate.version());
            return UpdateResult.STAGED;
        } catch (IOException e) {
            throw new IllegalStateException("Unable to stage a reviewed ViaVersion runtime", e);
        } finally {
            STORE_LOCK.unlock();
        }
    }

    private Set<String> artifactsToKeep(RuntimeArtifactDescriptor pending) {
        List<String> names = new ArrayList<>();
        names.add(pending.artifactName());
        names.add(RuntimeArtifactDescriptor.pinned().artifactName());
        readManifest(ACTIVE_MANIFEST).ifPresent(active -> names.add(active.artifactName()));
        return Set.copyOf(names);
    }

    private void addManifestCandidate(
            Map<RuntimeArtifactDescriptor, RuntimeCandidate> candidates,
            String manifest,
            CandidateSource source) {
        readManifest(manifest).ifPresent(artifact ->
                candidates.putIfAbsent(artifact, new RuntimeCandidate(artifact, source)));
    }

    private java.util.Optional<RuntimeArtifactDescriptor> readManifest(String fileName) {
        Path manifest = runtimeDirectory.resolve(fileName);
        if (!Files.isRegularFile(manifest, LinkOption.NOFOLLOW_LINKS)) {
            return java.util.Optional.empty();
        }
        try {
            if (Files.size(manifest) <= 0 || Files.size(manifest) > MAXIMUM_MANIFEST_BYTES) {
                throw new IOException("runtime manifest has an invalid size");
            }
            Properties properties = new Properties();
            try (InputStream input = Files.newInputStream(manifest)) {
                properties.load(input);
            }
            if (!REVIEWED_TRUST.equals(properties.getProperty("trust"))) {
                throw new IOException("runtime manifest lacks independent maintainer trust");
            }
            RuntimeArtifactDescriptor descriptor = new RuntimeArtifactDescriptor(
                    properties.getProperty("version"),
                    URI.create(properties.getProperty("url")),
                    properties.getProperty("sha256"));
            repositoryClient.validateArtifactTransport(descriptor.uri());
            return java.util.Optional.of(descriptor);
        } catch (IOException | IllegalArgumentException | IllegalStateException | NullPointerException e) {
            logger.warn("Ignoring invalid embedded protocol runtime manifest {}", manifest, e);
            deleteInvalidManifest(manifest, e);
            return java.util.Optional.empty();
        }
    }

    private void deleteInvalidManifest(Path manifest, Exception invalidManifest) {
        try {
            Files.deleteIfExists(manifest);
        } catch (IOException cleanupFailure) {
            invalidManifest.addSuppressed(cleanupFailure);
            logger.warn("Unable to remove invalid embedded protocol runtime manifest {}",
                    manifest, cleanupFailure);
        }
    }

    private boolean manifestHasArtifact(String fileName, RuntimeArtifactDescriptor artifact) {
        return readManifest(fileName).filter(artifact::equals).isPresent();
    }

    private void writeManifest(String fileName, RuntimeArtifactDescriptor artifact) throws IOException {
        String content = "trust=" + REVIEWED_TRUST + '\n'
                + "version=" + artifact.version() + '\n'
                + "url=" + artifact.uri() + '\n'
                + "sha256=" + artifact.sha256() + '\n';
        writeAtomically(runtimeDirectory.resolve(fileName), content);
    }

    private static void writeAtomically(Path target, String content) throws IOException {
        Path temporary = Files.createTempFile(target.getParent(), ".runtime-state-", ".tmp");
        try {
            Files.writeString(temporary, content, StandardCharsets.US_ASCII,
                    StandardOpenOption.TRUNCATE_EXISTING);
            RuntimeIo.applyOwnerOnlyPermissions(temporary);
            RuntimeIo.publishAtomically(temporary, target);
        } finally {
            Files.deleteIfExists(temporary);
        }
    }

    private void pruneArtifacts(Set<String> keepNames) {
        try (var files = Files.list(runtimeDirectory)) {
            files.filter(path -> Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS))
                    .filter(path -> path.getFileName().toString()
                            .matches("viaversion-common-[0-9A-Za-z._-]+\\.jar"))
                    .filter(path -> !keepNames.contains(path.getFileName().toString()))
                    .forEach(this::deleteObsoleteArtifact);
        } catch (IOException e) {
            logger.warn("Unable to prune obsolete embedded protocol runtime artifacts", e);
        }
    }

    private void deleteObsoleteArtifact(Path artifact) {
        try {
            Files.deleteIfExists(artifact);
        } catch (IOException e) {
            logger.warn("Unable to delete obsolete embedded protocol runtime {}", artifact, e);
        }
    }

    enum UpdateResult {
        STAGED,
        CURRENT
    }

    enum CandidateSource {
        PENDING("staged"),
        ACTIVE("previously active"),
        PINNED("build-pinned");

        private final String displayName;

        CandidateSource(String displayName) {
            this.displayName = displayName;
        }

        String displayName() {
            return displayName;
        }
    }

    record RuntimeCandidate(
            RuntimeArtifactDescriptor artifact,
            CandidateSource source) {
        RuntimeCandidate {
            Objects.requireNonNull(artifact, "artifact");
            Objects.requireNonNull(source, "source");
        }
    }
}
