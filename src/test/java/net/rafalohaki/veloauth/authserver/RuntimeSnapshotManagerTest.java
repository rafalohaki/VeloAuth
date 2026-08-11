package net.rafalohaki.veloauth.authserver;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.slf4j.Logger;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;

class RuntimeSnapshotManagerTest {

    private static final String REVIEWED_VERSION = "6.0.0-20270102.040506-7";
    private static final List<String> REQUIRED_ENTRIES = List.of(
            "com/viaversion/viaversion/ViaManagerImpl.class",
            "com/viaversion/viaversion/platform/ViaChannelInitializer.class",
            "com/viaversion/viaversion/protocols/v1_8to1_9/Protocol1_8To1_9.class");

    @TempDir
    private Path temporaryDirectory;

    private HttpServer server;

    @AfterEach
    void stopServer() {
        if (server != null) {
            server.stop(0);
        }
    }

    @Test
    void stageReviewedRuntime_ValidMaintainerDigest_ShouldDownloadOnlyArtifactAndActivateAfterRestart()
            throws Exception {
        byte[] artifact = testJar("reviewed");
        AtomicInteger artifactRequests = new AtomicInteger();
        URI repository = serveArtifact(artifact, artifactRequests);
        RuntimeArtifactDescriptor reviewed = descriptor(repository, sha256(artifact));
        RuntimeSnapshotManager manager = manager(repository, reviewed);

        RuntimeSnapshotManager.UpdateResult result =
                manager.stageReviewedRuntime("5.11.0", reviewed);

        assertEquals(RuntimeSnapshotManager.UpdateResult.STAGED, result);
        assertEquals(1, artifactRequests.get());
        Path pendingManifest = temporaryDirectory.resolve(RuntimeSnapshotManager.PENDING_MANIFEST);
        assertTrue(Files.readString(pendingManifest).contains("format=veloauth-runtime-v2"));
        assertFalse(Files.exists(temporaryDirectory.resolve(RuntimeSnapshotManager.ACTIVE_MANIFEST)));
        RuntimeSnapshotManager.RuntimeCandidate pending = manager.startupCandidates().getFirst();
        assertEquals(RuntimeSnapshotManager.CandidateSource.PENDING, pending.source());
        assertEquals(REVIEWED_VERSION, pending.artifact().version());

        manager.recordSuccessful(pending);

        assertFalse(Files.exists(pendingManifest));
        Path activeManifest = temporaryDirectory.resolve(RuntimeSnapshotManager.ACTIVE_MANIFEST);
        assertTrue(Files.readString(activeManifest).contains("format=veloauth-runtime-v2"));
        RuntimeSnapshotManager.RuntimeCandidate active = manager.startupCandidates().getFirst();
        assertEquals(RuntimeSnapshotManager.CandidateSource.ACTIVE, active.source());
        assertEquals(REVIEWED_VERSION, active.artifact().version());
        assertEquals(RuntimeSnapshotManager.UpdateResult.CURRENT,
                manager.stageReviewedRuntime(REVIEWED_VERSION, reviewed));
        assertEquals(1, artifactRequests.get());
    }

    @Test
    void stageReviewedRuntime_OriginMetadataAndChecksumMatchTamperedBytes_ShouldUseMaintainerDigestOnly()
            throws Exception {
        byte[] reviewedBytes = testJar("reviewed");
        byte[] originBytes = testJar("origin-tampered");
        AtomicInteger artifactRequests = new AtomicInteger();
        AtomicInteger metadataRequests = new AtomicInteger();
        AtomicInteger checksumRequests = new AtomicInteger();
        URI repository = serveUntrustedOrigin(
                originBytes, artifactRequests, metadataRequests, checksumRequests);
        RuntimeArtifactDescriptor reviewed = descriptor(repository, sha256(reviewedBytes));
        RuntimeSnapshotManager manager = manager(repository, reviewed);

        assertThrows(IllegalStateException.class,
                () -> manager.stageReviewedRuntime("5.11.0", reviewed));

        assertEquals(1, artifactRequests.get());
        assertEquals(0, metadataRequests.get(), "Runtime trust must not read mutable latest metadata");
        assertEquals(0, checksumRequests.get(), "Runtime trust must not read a same-origin checksum");
        assertFalse(Files.exists(temporaryDirectory.resolve(RuntimeSnapshotManager.PENDING_MANIFEST)));
        assertEquals(RuntimeSnapshotManager.CandidateSource.PINNED,
                manager.startupCandidates().getFirst().source());
    }

    @Test
    void stageReviewedRuntime_RepositoryRollback_ShouldKeepNewerCurrentWithoutNetwork() throws Exception {
        byte[] artifact = testJar("older");
        AtomicInteger requests = new AtomicInteger();
        URI repository = serveArtifact(artifact, requests);
        RuntimeArtifactDescriptor reviewed = descriptor(repository, sha256(artifact));
        RuntimeSnapshotManager manager = manager(repository, reviewed);

        RuntimeSnapshotManager.UpdateResult result = manager.stageReviewedRuntime(
                "7.0.0-20270203.040506-1", reviewed);

        assertEquals(RuntimeSnapshotManager.UpdateResult.CURRENT, result);
        assertEquals(0, requests.get());
        assertFalse(Files.exists(temporaryDirectory.resolve(RuntimeSnapshotManager.PENDING_MANIFEST)));
    }

    @Test
    void stageReviewedRuntime_EmptyCacheAndOfflineRepository_ShouldFailWithoutPublishingState()
            throws Exception {
        URI repository = stoppedRepository();
        RuntimeArtifactDescriptor reviewed = descriptor(repository, "0".repeat(64));
        RuntimeSnapshotManager manager = manager(repository, reviewed);

        assertThrows(IllegalStateException.class,
                () -> manager.stageReviewedRuntime("5.11.0", reviewed));

        assertFalse(Files.exists(temporaryDirectory.resolve(RuntimeSnapshotManager.PENDING_MANIFEST)));
        assertEquals(RuntimeSnapshotManager.CandidateSource.PINNED,
                manager.startupCandidates().getFirst().source());
    }

    @Test
    void startupCandidates_LegacyOriginTrustedManifest_ShouldRejectAndUsePinnedFallback()
            throws Exception {
        Files.createDirectories(temporaryDirectory);
        URI repository = URI.create("http://127.0.0.1:1/repository/");
        Path legacyManifest = temporaryDirectory.resolve(RuntimeSnapshotManager.PENDING_MANIFEST);
        writeManifest(legacyManifest, descriptor(repository, "0".repeat(64)), false);
        RuntimeSnapshotManager manager = manager(repository);

        List<RuntimeSnapshotManager.RuntimeCandidate> candidates = manager.startupCandidates();

        assertFalse(Files.exists(legacyManifest));
        assertEquals(1, candidates.size());
        assertEquals(RuntimeSnapshotManager.CandidateSource.PINNED,
                candidates.getFirst().source());
    }

    @ParameterizedTest
    @ValueSource(strings = {
            RuntimeSnapshotManager.PENDING_MANIFEST,
            RuntimeSnapshotManager.ACTIVE_MANIFEST
    })
    void startupCandidates_SelfAssertedFormatOnArbitraryDescriptor_ShouldRejectManifest(
            String manifestName) throws Exception {
        byte[] forgedBytes = testJar("forged");
        URI repository = URI.create("http://127.0.0.1:1/repository/");
        RuntimeArtifactDescriptor forged = descriptor(repository, sha256(forgedBytes));
        Files.createDirectories(temporaryDirectory);
        Files.write(temporaryDirectory.resolve(forged.artifactName()), forgedBytes);
        Path manifest = temporaryDirectory.resolve(manifestName);
        writeManifest(manifest, forged, true);
        RuntimeSnapshotManager manager = manager(repository);

        List<RuntimeSnapshotManager.RuntimeCandidate> candidates = manager.startupCandidates();

        assertFalse(Files.exists(manifest),
                "A mutable format marker must not authorize executable runtime bytes");
        assertEquals(1, candidates.size());
        assertEquals(RuntimeSnapshotManager.CandidateSource.PINNED,
                candidates.getFirst().source());
    }

    @Test
    void stageReviewedRuntime_DescriptorNotApprovedByBuild_ShouldRejectBeforeNetwork()
            throws Exception {
        URI repository = stoppedRepository();
        RuntimeArtifactDescriptor unapproved = descriptor(repository, "0".repeat(64));
        RuntimeSnapshotManager manager = manager(repository);

        assertThrows(IllegalArgumentException.class,
                () -> manager.stageReviewedRuntime("5.11.0", unapproved));

        assertFalse(Files.exists(temporaryDirectory.resolve(
                RuntimeSnapshotManager.PENDING_MANIFEST)));
    }

    @Test
    void startupCandidates_TrustedActiveCache_ShouldRemainKnownGoodWhileOffline() throws Exception {
        byte[] activeBytes = testJar("known-good");
        URI repository = URI.create("http://127.0.0.1:1/repository/");
        RuntimeArtifactDescriptor active = descriptor(repository, sha256(activeBytes));
        Files.createDirectories(temporaryDirectory);
        Files.write(temporaryDirectory.resolve(active.artifactName()), activeBytes);
        writeManifest(temporaryDirectory.resolve(RuntimeSnapshotManager.ACTIVE_MANIFEST), active, true);
        RuntimeSnapshotManager manager = manager(repository, active);

        RuntimeSnapshotManager.RuntimeCandidate candidate = manager.startupCandidates().getFirst();
        Path resolved = manager.resolve(candidate);

        assertEquals(RuntimeSnapshotManager.CandidateSource.ACTIVE, candidate.source());
        assertEquals(active.artifactName(), resolved.getFileName().toString());
        assertEquals(activeBytes.length, Files.size(resolved));
    }

    @Test
    void recordFailed_PendingCandidate_ShouldFallBackWithoutDeletingPinnedArtifact() throws Exception {
        byte[] artifact = testJar("pending");
        URI repository = serveArtifact(artifact, new AtomicInteger());
        RuntimeArtifactDescriptor reviewed = descriptor(repository, sha256(artifact));
        RuntimeSnapshotManager manager = manager(repository, reviewed);
        manager.stageReviewedRuntime("5.11.0", reviewed);
        RuntimeSnapshotManager.RuntimeCandidate pending = manager.startupCandidates().getFirst();

        manager.recordFailed(pending, new IllegalStateException("incompatible reviewed runtime"));

        assertFalse(Files.exists(temporaryDirectory.resolve(RuntimeSnapshotManager.PENDING_MANIFEST)));
        assertEquals(RuntimeSnapshotManager.CandidateSource.PINNED,
                manager.startupCandidates().getFirst().source());
    }

    @Test
    void recordSuccessful_PendingRemovalFailure_ShouldPreservePreviousActiveManifest() throws Exception {
        byte[] artifact = testJar("pending");
        URI repository = serveArtifact(artifact, new AtomicInteger());
        RuntimeArtifactDescriptor reviewed = descriptor(repository, sha256(artifact));
        RuntimeSnapshotManager manager = manager(repository, reviewed);
        manager.stageReviewedRuntime("5.11.0", reviewed);
        RuntimeSnapshotManager.RuntimeCandidate pending = manager.startupCandidates().getFirst();
        Path activeManifest = temporaryDirectory.resolve(RuntimeSnapshotManager.ACTIVE_MANIFEST);
        String previousActive = "previous-active-runtime\n";
        Files.writeString(activeManifest, previousActive);
        Path pendingManifest = temporaryDirectory.resolve(RuntimeSnapshotManager.PENDING_MANIFEST);
        Files.delete(pendingManifest);
        Files.createDirectory(pendingManifest);
        Files.writeString(pendingManifest.resolve("undeletable-child"), "block activation");

        assertThrows(IllegalStateException.class, () -> manager.recordSuccessful(pending));

        assertEquals(previousActive, Files.readString(activeManifest),
                "A failed pending cleanup must not partially replace the active runtime");
    }

    @Test
    void startupCandidates_ManifestOutsideRepository_ShouldRemoveItAndUsePinnedFallback()
            throws Exception {
        Files.createDirectories(temporaryDirectory);
        Path invalidManifest = temporaryDirectory.resolve(RuntimeSnapshotManager.ACTIVE_MANIFEST);
        RuntimeArtifactDescriptor outsideRepository = new RuntimeArtifactDescriptor(
                REVIEWED_VERSION,
                URI.create("https://untrusted.example/viaversion-common.jar"),
                "0".repeat(64));
        writeManifest(invalidManifest, outsideRepository, true);
        RuntimeSnapshotManager manager = manager(
                URI.create("http://127.0.0.1:1/repository/"), outsideRepository);

        List<RuntimeSnapshotManager.RuntimeCandidate> candidates = manager.startupCandidates();

        assertFalse(Files.exists(invalidManifest));
        assertEquals(1, candidates.size());
        assertEquals(RuntimeSnapshotManager.CandidateSource.PINNED,
                candidates.getFirst().source());
    }

    private RuntimeSnapshotManager manager(
            URI repository, RuntimeArtifactDescriptor... approvedDescriptors) {
        Set<RuntimeArtifactDescriptor> approved = approvedDescriptors.length == 0
                ? Set.of(RuntimeArtifactDescriptor.pinned())
                : Set.of(approvedDescriptors);
        return new RuntimeSnapshotManager(
                temporaryDirectory,
                repository,
                HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build(),
                mock(Logger.class),
                false,
                approved);
    }

    private RuntimeArtifactDescriptor descriptor(URI repository, String checksum) {
        return new RuntimeArtifactDescriptor(
                REVIEWED_VERSION,
                repository.resolve("viaversion-common-" + REVIEWED_VERSION + ".jar"),
                checksum);
    }

    private URI serveArtifact(byte[] artifact, AtomicInteger requests) throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        String root = "/repository/";
        addResponse(root + "viaversion-common-" + REVIEWED_VERSION + ".jar", artifact, requests);
        server.start();
        return URI.create("http://127.0.0.1:" + server.getAddress().getPort() + root);
    }

    private URI serveUntrustedOrigin(
            byte[] artifact,
            AtomicInteger artifactRequests,
            AtomicInteger metadataRequests,
            AtomicInteger checksumRequests) throws Exception {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        String root = "/repository/";
        String artifactName = "viaversion-common-" + REVIEWED_VERSION + ".jar";
        addResponse(root + "maven-metadata.xml", "<metadata><latest>evil</latest></metadata>",
                metadataRequests);
        addResponse(root + artifactName, artifact, artifactRequests);
        addResponse(root + artifactName + ".sha256", sha256(artifact), checksumRequests);
        server.start();
        return URI.create("http://127.0.0.1:" + server.getAddress().getPort() + root);
    }

    private URI stoppedRepository() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        int port = server.getAddress().getPort();
        server.start();
        server.stop(0);
        server = null;
        return URI.create("http://127.0.0.1:" + port + "/repository/");
    }

    private static void writeManifest(
            Path manifest,
            RuntimeArtifactDescriptor descriptor,
            boolean currentFormat) throws IOException {
        String format = currentFormat
                ? "format=" + RuntimeSnapshotManager.MANIFEST_FORMAT + '\n'
                : "";
        Files.writeString(manifest,
                format
                        + "version=" + descriptor.version() + '\n'
                        + "url=" + descriptor.uri() + '\n'
                        + "sha256=" + descriptor.sha256() + '\n');
    }

    private void addResponse(String path, String response, AtomicInteger requests) {
        addResponse(path, response.getBytes(StandardCharsets.UTF_8), requests);
    }

    private void addResponse(String path, byte[] response, AtomicInteger requests) {
        server.createContext(path, exchange -> respond(exchange, response, requests));
    }

    private static void respond(HttpExchange exchange, byte[] response, AtomicInteger requests)
            throws IOException {
        requests.incrementAndGet();
        exchange.sendResponseHeaders(200, response.length);
        exchange.getResponseBody().write(response);
        exchange.close();
    }

    private static byte[] testJar(String marker) throws IOException {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        try (JarOutputStream jar = new JarOutputStream(output)) {
            for (String name : REQUIRED_ENTRIES) {
                jar.putNextEntry(new JarEntry(name));
                jar.write((name + ':' + marker).getBytes(StandardCharsets.UTF_8));
                jar.closeEntry();
            }
        }
        return output.toByteArray();
    }

    private static String sha256(byte[] bytes) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
    }
}
