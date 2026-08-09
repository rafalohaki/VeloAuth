package net.rafalohaki.veloauth.authserver;

import com.viaversion.viaversion.ViaManagerImpl;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.embedded.EmbeddedChannel;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.slf4j.Logger;

import java.nio.file.Path;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.List;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;

class ManagedProtocolRuntimeTest {

    private static final List<String> REQUIRED_ENTRIES = List.of(
            "com/viaversion/viaversion/ViaManagerImpl.class",
            "com/viaversion/viaversion/platform/ViaChannelInitializer.class",
            "com/viaversion/viaversion/protocols/v1_8to1_9/Protocol1_8To1_9.class");

    @TempDir
    private Path temporaryDirectory;

    @Test
    void open_PinnedRuntime_ShouldLoadAllMappingsInIsolationAndInjectNettyHandlers() throws Exception {
        Path artifact = Path.of(ViaManagerImpl.class.getProtectionDomain()
                .getCodeSource().getLocation().toURI());

        ManagedProtocolRuntime runtime = ManagedProtocolRuntime.open(
                artifact, temporaryDirectory, mock(Logger.class), "test");
        try {
            assertEquals(47, runtime.minimumProtocol());
            assertEquals(776, runtime.maximumProtocol());
            assertEquals("1.8", runtime.minimumVersionName());
            assertEquals("26.2", runtime.maximumVersionName());
            assertTrue(runtime.supportsProtocol(47));
            assertTrue(runtime.supportsProtocol(340));
            assertTrue(runtime.supportsProtocol(754));
            assertTrue(runtime.supportsProtocol(769));
            assertTrue(runtime.supportsProtocol(776));
            assertFalse(runtime.supportsProtocol(46));

            EmbeddedChannel channel = new EmbeddedChannel();
            channel.pipeline().addLast("codec", new ChannelInboundHandlerAdapter());
            runtime.inject(channel);

            assertTrue(channel.pipeline().names().contains("veloauth-via-decoder"));
            assertTrue(channel.pipeline().names().contains("veloauth-via-encoder"));
            channel.finishAndReleaseAll();
        } finally {
            runtime.close();
        }

        assertThrows(IllegalStateException.class, () -> runtime.supportsProtocol(47));
        runtime.close();
    }

    @Test
    void open_IncompatiblePendingRuntime_ShouldFallBackToLastActiveRuntime() throws Exception {
        Path sourceArtifact = Path.of(ViaManagerImpl.class.getProtectionDomain()
                .getCodeSource().getLocation().toURI());
        Path runtimeDirectory = temporaryDirectory.resolve("runtime");
        Files.createDirectories(runtimeDirectory);

        String activeVersion = "9.9.8-active";
        Path activeArtifact = runtimeDirectory.resolve("viaversion-common-" + activeVersion + ".jar");
        Files.copy(sourceArtifact, activeArtifact);
        writeManifest(runtimeDirectory.resolve(RuntimeSnapshotManager.ACTIVE_MANIFEST),
                activeVersion, sha256(activeArtifact));

        String pendingVersion = "9.9.9-broken";
        Path pendingArtifact = runtimeDirectory.resolve("viaversion-common-" + pendingVersion + ".jar");
        writeInvalidRuntime(pendingArtifact);
        writeManifest(runtimeDirectory.resolve(RuntimeSnapshotManager.PENDING_MANIFEST),
                pendingVersion, sha256(pendingArtifact));

        ManagedProtocolRuntime runtime = ManagedProtocolRuntime.open(
                temporaryDirectory, mock(Logger.class), "test");
        try {
            assertEquals(activeVersion, runtime.runtimeVersion());
            assertTrue(runtime.supportsProtocol(47));
            assertFalse(Files.exists(runtimeDirectory.resolve(RuntimeSnapshotManager.PENDING_MANIFEST)));
            assertTrue(Files.exists(runtimeDirectory.resolve(RuntimeSnapshotManager.ACTIVE_MANIFEST)));
        } finally {
            runtime.close();
        }
    }

    private static void writeManifest(Path manifest, String version, String sha256) throws Exception {
        String baseUrl = "https://repo.viaversion.com/com/viaversion/viaversion-common/";
        Files.writeString(manifest,
                "version=" + version + '\n'
                        + "url=" + baseUrl + version + "/viaversion-common-" + version + ".jar\n"
                        + "sha256=" + sha256 + '\n');
    }

    private static void writeInvalidRuntime(Path artifact) throws Exception {
        try (JarOutputStream jar = new JarOutputStream(Files.newOutputStream(artifact))) {
            for (String name : REQUIRED_ENTRIES) {
                jar.putNextEntry(new JarEntry(name));
                jar.write("not-bytecode".getBytes(java.nio.charset.StandardCharsets.US_ASCII));
                jar.closeEntry();
            }
        }
    }

    private static String sha256(Path artifact) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                .digest(Files.readAllBytes(artifact)));
    }
}
