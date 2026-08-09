package net.rafalohaki.veloauth.authserver;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
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
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.HexFormat;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;

class RuntimeSnapshotManagerTest {

    private static final String SNAPSHOT_LINE = "6.0.0-SNAPSHOT";
    private static final String RESOLVED_VERSION = "6.0.0-20270102.040506-7";
    private static final List<String> REQUIRED_ENTRIES = List.of(
            "com/viaversion/viaversion/ViaManagerImpl.class",
            "com/viaversion/viaversion/platform/ViaChannelInitializer.class",
            "com/viaversion/viaversion/protocols/v1_8to1_9/Protocol1_8To1_9.class");
    private static final Instant CHECK_TIME = Instant.parse("2027-01-02T05:00:00Z");

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
    void stageLatestSnapshot_ValidCandidate_ShouldActivateOnlyAfterSuccessfulRestart() throws Exception {
        byte[] artifact = testJar();
        AtomicInteger requests = new AtomicInteger();
        URI repository = serveRepository(artifact, sha256(artifact), requests);
        RuntimeSnapshotManager manager = manager(repository, Clock.fixed(CHECK_TIME, ZoneOffset.UTC));

        RuntimeSnapshotManager.UpdateResult result = manager.stageLatestSnapshot("5.11.0");

        assertEquals(RuntimeSnapshotManager.UpdateResult.STAGED, result);
        assertEquals(4, requests.get());
        assertTrue(Files.exists(temporaryDirectory.resolve(RuntimeSnapshotManager.PENDING_MANIFEST)));
        assertFalse(Files.exists(temporaryDirectory.resolve(RuntimeSnapshotManager.ACTIVE_MANIFEST)));
        RuntimeSnapshotManager.RuntimeCandidate pending = manager.startupCandidates().getFirst();
        assertEquals(RuntimeSnapshotManager.CandidateSource.PENDING, pending.source());
        assertEquals(RESOLVED_VERSION, pending.artifact().version());

        manager.recordSuccessful(pending);

        assertFalse(Files.exists(temporaryDirectory.resolve(RuntimeSnapshotManager.PENDING_MANIFEST)));
        assertTrue(Files.exists(temporaryDirectory.resolve(RuntimeSnapshotManager.ACTIVE_MANIFEST)));
        RuntimeSnapshotManager.RuntimeCandidate active = manager.startupCandidates().getFirst();
        assertEquals(RuntimeSnapshotManager.CandidateSource.ACTIVE, active.source());
        assertEquals(RESOLVED_VERSION, active.artifact().version());

        RuntimeSnapshotManager throttled = manager(repository, Clock.offset(
                Clock.fixed(CHECK_TIME, ZoneOffset.UTC), Duration.ofMinutes(1)));
        assertEquals(RuntimeSnapshotManager.UpdateResult.THROTTLED,
                throttled.stageLatestSnapshot(RESOLVED_VERSION));
        assertEquals(4, requests.get());

        RuntimeSnapshotManager nextBoot = manager(repository, Clock.offset(
                Clock.fixed(CHECK_TIME, ZoneOffset.UTC), Duration.ofMinutes(16)));
        assertEquals(RuntimeSnapshotManager.UpdateResult.CURRENT,
                nextBoot.stageLatestSnapshot(RESOLVED_VERSION));
        assertEquals(6, requests.get());
    }

    @Test
    void stageLatestSnapshot_ChecksumMismatch_ShouldNotPublishPendingManifest() throws Exception {
        byte[] artifact = testJar();
        URI repository = serveRepository(artifact, "0".repeat(64), new AtomicInteger());
        RuntimeSnapshotManager manager = manager(repository, Clock.fixed(CHECK_TIME, ZoneOffset.UTC));

        assertThrows(IllegalStateException.class,
                () -> manager.stageLatestSnapshot("5.11.0"));

        assertFalse(Files.exists(temporaryDirectory.resolve(RuntimeSnapshotManager.PENDING_MANIFEST)));
        assertTrue(manager.startupCandidates().stream()
                .allMatch(candidate -> candidate.source() == RuntimeSnapshotManager.CandidateSource.PINNED));
    }

    @Test
    void stageLatestSnapshot_RepositoryRollback_ShouldKeepNewerActiveRuntime() throws Exception {
        byte[] artifact = testJar();
        AtomicInteger requests = new AtomicInteger();
        URI repository = serveRepository(artifact, sha256(artifact), requests);
        RuntimeSnapshotManager manager = manager(repository, Clock.fixed(CHECK_TIME, ZoneOffset.UTC));

        RuntimeSnapshotManager.UpdateResult result = manager.stageLatestSnapshot(
                "7.0.0-20270203.040506-1");

        assertEquals(RuntimeSnapshotManager.UpdateResult.CURRENT, result);
        assertEquals(2, requests.get());
        assertFalse(Files.exists(temporaryDirectory.resolve(RuntimeSnapshotManager.PENDING_MANIFEST)));
    }

    @Test
    void recordFailed_PendingCandidate_ShouldFallBackWithoutDeletingPinnedArtifact() throws Exception {
        byte[] artifact = testJar();
        URI repository = serveRepository(artifact, sha256(artifact), new AtomicInteger());
        RuntimeSnapshotManager manager = manager(repository, Clock.fixed(CHECK_TIME, ZoneOffset.UTC));
        manager.stageLatestSnapshot("5.11.0");
        RuntimeSnapshotManager.RuntimeCandidate pending = manager.startupCandidates().getFirst();

        manager.recordFailed(pending, new IllegalStateException("incompatible snapshot"));

        assertFalse(Files.exists(temporaryDirectory.resolve(RuntimeSnapshotManager.PENDING_MANIFEST)));
        assertEquals(RuntimeSnapshotManager.CandidateSource.PINNED,
                manager.startupCandidates().getFirst().source());
    }

    @Test
    void startupCandidates_InvalidRegularManifest_ShouldRemoveItAndUsePinnedFallback() throws Exception {
        Files.createDirectories(temporaryDirectory);
        Path invalidManifest = temporaryDirectory.resolve(RuntimeSnapshotManager.PENDING_MANIFEST);
        Files.writeString(invalidManifest, "not-a-runtime-manifest");
        RuntimeSnapshotManager manager = manager(
                URI.create("http://127.0.0.1:1/repository/"),
                Clock.fixed(CHECK_TIME, ZoneOffset.UTC));

        List<RuntimeSnapshotManager.RuntimeCandidate> candidates = manager.startupCandidates();

        assertFalse(Files.exists(invalidManifest));
        assertEquals(1, candidates.size());
        assertEquals(RuntimeSnapshotManager.CandidateSource.PINNED,
                candidates.getFirst().source());
    }

    @Test
    void startupCandidates_ManifestOutsideRepository_ShouldRemoveItAndUsePinnedFallback() throws Exception {
        Files.createDirectories(temporaryDirectory);
        Path invalidManifest = temporaryDirectory.resolve(RuntimeSnapshotManager.ACTIVE_MANIFEST);
        Files.writeString(invalidManifest,
                "version=6.0.0-20270102.040506-7\n"
                        + "url=https://untrusted.example/viaversion-common.jar\n"
                        + "sha256=" + "0".repeat(64) + '\n');
        RuntimeSnapshotManager manager = manager(
                URI.create("http://127.0.0.1:1/repository/"),
                Clock.fixed(CHECK_TIME, ZoneOffset.UTC));

        List<RuntimeSnapshotManager.RuntimeCandidate> candidates = manager.startupCandidates();

        assertFalse(Files.exists(invalidManifest));
        assertEquals(1, candidates.size());
        assertEquals(RuntimeSnapshotManager.CandidateSource.PINNED,
                candidates.getFirst().source());
    }

    @Test
    void stageLatestSnapshot_MetadataWithExternalEntity_ShouldRejectWithoutResolvingEntity() throws Exception {
        AtomicInteger externalEntityRequests = new AtomicInteger();
        URI repository = serveExternalEntityMetadata(externalEntityRequests);
        RuntimeSnapshotManager manager = manager(repository, Clock.fixed(CHECK_TIME, ZoneOffset.UTC));

        assertThrows(IllegalStateException.class,
                () -> manager.stageLatestSnapshot("5.11.0"));

        assertEquals(0, externalEntityRequests.get(),
                "Repository metadata must never resolve external XML entities");
        assertFalse(Files.exists(temporaryDirectory.resolve(RuntimeSnapshotManager.PENDING_MANIFEST)));
    }

    private RuntimeSnapshotManager manager(URI repository, Clock clock) {
        return new RuntimeSnapshotManager(
                temporaryDirectory,
                repository,
                HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build(),
                mock(Logger.class),
                false,
                clock);
    }

    private URI serveRepository(byte[] artifact, String checksum, AtomicInteger requests) throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        String root = "/repository/com/viaversion/viaversion-common/";
        addResponse(root + "maven-metadata.xml",
                "<metadata><versioning><latest>" + SNAPSHOT_LINE
                        + "</latest></versioning></metadata>", requests);
        addResponse(root + SNAPSHOT_LINE + "/maven-metadata.xml",
                "<metadata><versioning><snapshotVersions><snapshotVersion>"
                        + "<extension>jar</extension><value>" + RESOLVED_VERSION
                        + "</value></snapshotVersion></snapshotVersions></versioning></metadata>", requests);
        String artifactPath = root + SNAPSHOT_LINE + "/viaversion-common-" + RESOLVED_VERSION + ".jar";
        addResponse(artifactPath, artifact, requests);
        addResponse(artifactPath + ".sha256", checksum, requests);
        server.start();
        return URI.create("http://127.0.0.1:" + server.getAddress().getPort() + root);
    }

    private URI serveExternalEntityMetadata(AtomicInteger externalEntityRequests) throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        String root = "/repository/com/viaversion/viaversion-common/";
        String entityUri = "http://127.0.0.1:" + server.getAddress().getPort() + "/external-entity";
        String metadata = "<!DOCTYPE metadata [<!ENTITY xxe SYSTEM \"" + entityUri + "\">]>"
                + "<metadata><versioning><latest>&xxe;</latest></versioning></metadata>";
        addResponse(root + "maven-metadata.xml", metadata, new AtomicInteger());
        addResponse("/external-entity", "6.0.0-SNAPSHOT", externalEntityRequests);
        server.start();
        return URI.create("http://127.0.0.1:" + server.getAddress().getPort() + root);
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

    private static byte[] testJar() throws IOException {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        try (JarOutputStream jar = new JarOutputStream(output)) {
            for (String name : REQUIRED_ENTRIES) {
                jar.putNextEntry(new JarEntry(name));
                jar.write(name.getBytes(StandardCharsets.UTF_8));
                jar.closeEntry();
            }
        }
        return output.toByteArray();
    }

    private static String sha256(byte[] bytes) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
    }
}
