package net.rafalohaki.veloauth.authserver;

import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.slf4j.Logger;

import java.io.ByteArrayOutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;

class RuntimeArtifactManagerTest {

    private static final String RUNTIME_VERSION = "9.9.9-test";
    private static final String RUNTIME_ARTIFACT_NAME =
            "viaversion-common-" + RUNTIME_VERSION + ".jar";
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
    void resolve_ValidDownload_ShouldPublishAtomicallyAndReuseOfflineCache() throws Exception {
        byte[] artifact = testJar();
        AtomicInteger requests = new AtomicInteger();
        URI uri = serve(artifact, 200, requests);
        RuntimeArtifactManager manager = manager(uri, sha256(artifact), false);

        Path resolved = manager.resolve();
        server.stop(0);
        server = null;
        Path cached = manager.resolve();

        assertEquals(resolved, cached);
        assertArrayEquals(artifact, Files.readAllBytes(cached));
        assertEquals(1, requests.get());
        try (var entries = Files.list(temporaryDirectory)) {
            assertTrue(entries.noneMatch(path -> path.getFileName().toString().endsWith(".download")));
        }
    }

    @Test
    void resolve_InvalidCachedArtifact_ShouldReplaceItWithVerifiedBytes() throws Exception {
        byte[] artifact = testJar();
        Files.createDirectories(temporaryDirectory);
        Path target = temporaryDirectory.resolve(RUNTIME_ARTIFACT_NAME);
        Files.writeString(target, "tampered");
        AtomicInteger requests = new AtomicInteger();
        RuntimeArtifactManager manager = manager(serve(artifact, 200, requests), sha256(artifact), false);

        Path resolved = manager.resolve();

        assertArrayEquals(artifact, Files.readAllBytes(resolved));
        assertEquals(1, requests.get());
    }

    @Test
    void resolve_ChecksumMismatch_ShouldFailClosedWithoutPublishingArtifact() throws Exception {
        byte[] artifact = testJar();
        RuntimeArtifactManager manager = manager(
                serve(artifact, 200, new AtomicInteger()), "0".repeat(64), false);

        assertThrows(IllegalStateException.class, manager::resolve);

        assertFalse(Files.exists(temporaryDirectory.resolve(RUNTIME_ARTIFACT_NAME)));
        try (var entries = Files.list(temporaryDirectory)) {
            assertTrue(entries.noneMatch(path -> path.getFileName().toString().endsWith(".download")));
        }
    }

    @Test
    void resolve_NonHttpsProductionTransport_ShouldRejectBeforeRequest() {
        AtomicInteger requests = new AtomicInteger();
        RuntimeArtifactManager manager = manager(
                serve(new byte[]{1}, 200, requests), "0".repeat(64), true);

        assertThrows(IllegalStateException.class, manager::resolve);
        assertEquals(0, requests.get());
    }

    @Test
    void resolve_ConcurrentManagersForSameArtifact_ShouldDownloadOnce() throws Exception {
        byte[] artifact = testJar();
        AtomicInteger requests = new AtomicInteger();
        CountDownLatch requestBarrier = new CountDownLatch(2);
        CountDownLatch releaseResponses = new CountDownLatch(1);
        URI uri = serveBlocking(artifact, requests, requestBarrier, releaseResponses);
        RuntimeArtifactManager first = manager(uri, sha256(artifact), false);
        RuntimeArtifactManager second = manager(uri, sha256(artifact), false);
        CountDownLatch start = new CountDownLatch(1);

        try (var executor = Executors.newVirtualThreadPerTaskExecutor()) {
            var firstResult = executor.submit(() -> {
                start.await();
                return first.resolve();
            });
            var secondResult = executor.submit(() -> {
                start.await();
                return second.resolve();
            });
            start.countDown();

            boolean duplicateRequestObserved = requestBarrier.await(300, TimeUnit.MILLISECONDS);
            releaseResponses.countDown();
            assertEquals(firstResult.get(), secondResult.get());
            assertFalse(duplicateRequestObserved,
                    "a second manager must wait until the first publication is complete");
        }

        assertEquals(1, requests.get(),
                "one process-wide publication lock should prevent duplicate downloads");
    }

    private RuntimeArtifactManager manager(URI uri, String digest, boolean requireHttps) {
        return new RuntimeArtifactManager(
                temporaryDirectory,
                new RuntimeArtifactDescriptor(RUNTIME_VERSION, uri, digest),
                HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build(),
                mock(Logger.class),
                requireHttps);
    }

    private URI serve(byte[] response, int status, AtomicInteger requests) {
        try {
            server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            server.createContext("/runtime.jar", exchange -> {
                requests.incrementAndGet();
                exchange.sendResponseHeaders(status, response.length);
                exchange.getResponseBody().write(response);
                exchange.close();
            });
            server.start();
            return URI.create("http://127.0.0.1:" + server.getAddress().getPort() + "/runtime.jar");
        } catch (java.io.IOException e) {
            throw new IllegalStateException(e);
        }
    }

    private URI serveBlocking(
            byte[] response,
            AtomicInteger requests,
            CountDownLatch requestBarrier,
            CountDownLatch releaseResponses) {
        try {
            server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            server.createContext("/runtime.jar", exchange -> {
                requests.incrementAndGet();
                requestBarrier.countDown();
                try {
                    releaseResponses.await(2, TimeUnit.SECONDS);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
                exchange.sendResponseHeaders(200, response.length);
                exchange.getResponseBody().write(response);
                exchange.close();
            });
            server.start();
            return URI.create("http://127.0.0.1:" + server.getAddress().getPort() + "/runtime.jar");
        } catch (java.io.IOException e) {
            throw new IllegalStateException(e);
        }
    }

    private static byte[] testJar() throws Exception {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        try (JarOutputStream jar = new JarOutputStream(output)) {
            for (String name : REQUIRED_ENTRIES) {
                jar.putNextEntry(new JarEntry(name));
                jar.write(name.getBytes(java.nio.charset.StandardCharsets.UTF_8));
                jar.closeEntry();
            }
        }
        return output.toByteArray();
    }

    private static String sha256(byte[] bytes) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
    }
}
