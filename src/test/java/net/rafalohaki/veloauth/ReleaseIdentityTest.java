package net.rafalohaki.veloauth;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.w3c.dom.Element;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.Properties;
import java.util.concurrent.TimeUnit;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarOutputStream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ReleaseIdentityTest {

    private static final String VERSION = "1.5.0";
    private static final String EXPECTED_TAG = "v1.5.0";
    private static final String BUILD_CONSTANTS_CLASS =
            "net/rafalohaki/veloauth/BuildConstants.class";
    private static final String POM_PROPERTIES =
            "META-INF/maven/net.rafalohaki.veloauth/veloauth/pom.properties";
    private static final Path VERIFIER = Path.of("scripts", "verify-release-identity.sh")
            .toAbsolutePath().normalize();

    @TempDir
    Path tempDir;

    @Test
    void generatedMetadata_ProjectVersion_MatchesFilteredOutputsAndOptionalJar() throws Exception {
        String projectVersion = readProjectVersion(Path.of("pom.xml"));
        assertEquals(projectVersion, BuildConstants.VERSION,
                "Generated BuildConstants must use the Maven project version");

        try (InputStream input = getClass().getClassLoader().getResourceAsStream("velocity-plugin.json")) {
            assertNotNull(input, "Filtered velocity-plugin.json must be available on the test classpath");
            JsonObject metadata = JsonParser.parseReader(
                    new java.io.InputStreamReader(input, StandardCharsets.UTF_8))
                    .getAsJsonObject();
            assertEquals(projectVersion, metadata.get("version").getAsString(),
                    "Filtered plugin metadata must use the Maven project version");
        }

        String releaseJar = System.getProperty("veloauth.release.jar");
        if (releaseJar != null && !releaseJar.isBlank()) {
            assertReleaseJarIdentity(Path.of(releaseJar), projectVersion);
        }
    }

    @Test
    void verifier_ConsistentFixture_Succeeds() throws Exception {
        Fixture fixture = createFixture(VERSION);

        VerificationResult result = runVerifier(fixture, EXPECTED_TAG);

        assertEquals(0, result.exitCode(), result.output());
        assertTrue(result.output().contains("Verified release identity 1.5.0 (v1.5.0)"), result.output());
    }

    @Test
    void verifier_ConsistentFixtureUnderColonPath_Succeeds() throws Exception {
        Fixture fixture = createFixture(VERSION, "identity fixture [safe]: colon", validBuildConstants());

        VerificationResult result = runVerifier(fixture, EXPECTED_TAG);

        assertEquals(0, result.exitCode(), result.output());
        assertTrue(result.output().contains("Verified release identity 1.5.0 (v1.5.0)"), result.output());
    }

    @Test
    void verifier_ConsistentFixture_DoesNotInvokeMaven() throws Exception {
        Fixture fixture = createFixture(VERSION);

        VerificationResult result = runVerifier(fixture, EXPECTED_TAG);

        assertEquals(0, result.exitCode(), result.output());
        assertTrue(Files.notExists(fixture.mavenMarker()),
                "Offline identity verification must not invoke Maven or the wrapper");
    }

    @Test
    void verifier_OnlyNestedVersion_FailsClosed() throws Exception {
        Fixture fixture = createFixture(VERSION);
        Files.writeString(fixture.root().resolve("pom.xml"), """
                <project xmlns="http://maven.apache.org/POM/4.0.0">
                  <modelVersion>4.0.0</modelVersion>
                  <parent>
                    <groupId>net.rafalohaki</groupId>
                    <artifactId>parent</artifactId>
                    <version>1.5.0</version>
                  </parent>
                  <artifactId>veloauth</artifactId>
                </project>
                """, StandardCharsets.UTF_8);

        VerificationResult result = runVerifier(fixture, EXPECTED_TAG);

        assertEquals(1, result.exitCode(), result.output());
        assertTrue(result.output().contains(
                "Maven project must contain exactly one direct release version"), result.output());
    }

    @Test
    void verifier_DuplicateDirectVersions_FailsClosed() throws Exception {
        Fixture fixture = createFixture(VERSION);
        Files.writeString(fixture.root().resolve("pom.xml"), """
                <project xmlns="http://maven.apache.org/POM/4.0.0">
                  <modelVersion>4.0.0</modelVersion>
                  <groupId>net.rafalohaki.veloauth</groupId>
                  <artifactId>veloauth</artifactId>
                  <version>1.5.0</version>
                  <version>1.5.0</version>
                </project>
                """, StandardCharsets.UTF_8);

        VerificationResult result = runVerifier(fixture, EXPECTED_TAG);

        assertEquals(1, result.exitCode(), result.output());
        assertTrue(result.output().contains(
                "Maven project must contain exactly one direct release version"), result.output());
    }

    @Test
    void verifier_MismatchedTag_FailsWithSpecificDiagnostic() throws Exception {
        Fixture fixture = createFixture(VERSION);

        VerificationResult result = runVerifier(fixture, "v1.5.1");

        assertEquals(1, result.exitCode(), result.output());
        assertTrue(result.output().contains(
                "Release tag mismatch: expected v1.5.0, found v1.5.1"), result.output());
    }

    @Test
    void verifier_MismatchedPluginMetadata_FailsWithSpecificDiagnostic() throws Exception {
        Fixture fixture = createFixture("1.4.0");

        VerificationResult result = runVerifier(fixture, EXPECTED_TAG);

        assertEquals(1, result.exitCode(), result.output());
        assertTrue(result.output().contains(
                "velocity-plugin.json version mismatch: expected 1.5.0, found 1.4.0"), result.output());
    }

    @Test
    void verifier_MissingBuildConstants_FailsClosed() throws Exception {
        Fixture fixture = createFixture(VERSION, "identity fixture [safe] missing class", null);

        VerificationResult result = runVerifier(fixture, EXPECTED_TAG);

        assertEquals(1, result.exitCode(), result.output());
        assertTrue(result.output().contains("Failed to inspect packaged BuildConstants"), result.output());
    }

    @Test
    void verifier_MalformedBuildConstants_FailsClosed() throws Exception {
        Fixture fixture = createFixture(VERSION, "identity fixture [safe] malformed class",
                "not a Java class".getBytes(StandardCharsets.UTF_8));

        VerificationResult result = runVerifier(fixture, EXPECTED_TAG);

        assertEquals(1, result.exitCode(), result.output());
        assertTrue(result.output().contains("Failed to inspect packaged BuildConstants"), result.output());
    }

    @Test
    void verifier_MultipleCandidateJars_FailsWithSpecificDiagnostic() throws Exception {
        Fixture fixture = createFixture(VERSION);
        Files.copy(fixture.jar(), fixture.root().resolve("target/veloauth-1.5.1.jar"));

        VerificationResult result = runVerifier(fixture, EXPECTED_TAG);

        assertEquals(1, result.exitCode(), result.output());
        assertTrue(result.output().contains(
                "Expected exactly one target/veloauth-*.jar, found 2"), result.output());
    }

    @Test
    void verifier_MissingChecksum_FailsWithSpecificDiagnostic() throws Exception {
        Fixture fixture = createFixture(VERSION);
        Files.delete(fixture.checksum());

        VerificationResult result = runVerifier(fixture, EXPECTED_TAG);

        assertEquals(1, result.exitCode(), result.output());
        assertTrue(result.output().contains(
                "Missing release checksum: veloauth-1.5.0.jar.sha256"), result.output());
    }

    @Test
    void verifier_MultipleChecksumRecords_FailsWithSpecificDiagnostic() throws Exception {
        Fixture fixture = createFixture(VERSION);
        Files.writeString(fixture.checksum(),
                fixture.sha256() + "  duplicate.jar\n", StandardCharsets.UTF_8,
                java.nio.file.StandardOpenOption.APPEND);

        VerificationResult result = runVerifier(fixture, EXPECTED_TAG);

        assertEquals(1, result.exitCode(), result.output());
        assertTrue(result.output().contains(
                "Malformed release checksum: expected one nonblank record"), result.output());
    }

    @Test
    void verifier_ManifestProducerPresentWithoutManifest_FailsClosed() throws Exception {
        Fixture fixture = createFixture(VERSION);
        Files.createDirectories(fixture.root().resolve("scripts"));
        Files.writeString(fixture.root().resolve("scripts/create-release-manifest.sh"), "fixture");

        VerificationResult result = runVerifier(fixture, EXPECTED_TAG);

        assertEquals(1, result.exitCode(), result.output());
        assertTrue(result.output().contains(
                "Missing release manifest: veloauth-1.5.0.jar.manifest.json"), result.output());
    }

    @Test
    void verifier_PresentManifestWithWrongVersion_FailsWithSpecificDiagnostic() throws Exception {
        Fixture fixture = createFixture(VERSION);
        Files.writeString(fixture.manifest(), """
                {"artifact":"veloauth-1.5.0.jar","version":"1.4.0","sha256":"%s"}
                """.formatted(fixture.sha256()), StandardCharsets.UTF_8);

        VerificationResult result = runVerifier(fixture, EXPECTED_TAG);

        assertEquals(1, result.exitCode(), result.output());
        assertTrue(result.output().contains(
                "Release manifest version mismatch: expected 1.5.0, found 1.4.0"), result.output());
    }

    @Test
    void verifier_TestOverridesWithoutTestMode_FailsBeforeUsingThem() throws Exception {
        Fixture fixture = createFixture(VERSION);
        ProcessBuilder processBuilder = new ProcessBuilder(VERIFIER.toString(), EXPECTED_TAG);
        processBuilder.redirectErrorStream(true);
        processBuilder.environment().put("VELOAUTH_RELEASE_IDENTITY_PROJECT_DIR", fixture.root().toString());

        VerificationResult result = runProcess(processBuilder);

        assertEquals(1, result.exitCode(), result.output());
        assertTrue(result.output().contains(
                "Test-only release identity overrides require VELOAUTH_RELEASE_IDENTITY_TEST_MODE=true"),
                result.output());
    }

    private Fixture createFixture(String pluginMetadataVersion) throws Exception {
        return createFixture(pluginMetadataVersion, "identity fixture [safe]", validBuildConstants());
    }

    private Fixture createFixture(
            String pluginMetadataVersion, String rootName, byte[] buildConstantsContent) throws Exception {
        Path root = tempDir.resolve(rootName);
        Path target = root.resolve("target");
        Files.createDirectories(target);
        Path temporary = Files.createDirectory(root.resolve("temporary"));
        Files.writeString(root.resolve("pom.xml"), """
                <project xmlns="http://maven.apache.org/POM/4.0.0">
                  <modelVersion>4.0.0</modelVersion>
                  <groupId>net.rafalohaki.veloauth</groupId>
                  <artifactId>veloauth</artifactId>
                  <version>1.5.0</version>
                </project>
                """, StandardCharsets.UTF_8);
        Path mavenMarker = root.resolve("maven-invoked");
        Path fakeMaven = root.resolve("mvnw");
        Files.writeString(fakeMaven, """
                #!/usr/bin/env bash
                set -euo pipefail
                : >"$(dirname -- "$0")/maven-invoked"
                echo "Release identity verifier invoked Maven" >&2
                exit 97
                """, StandardCharsets.UTF_8);
        assertTrue(fakeMaven.toFile().setExecutable(true), "Poison Maven wrapper must be executable");

        Path jar = target.resolve("veloauth-1.5.0.jar");
        writeFixtureJar(jar, pluginMetadataVersion, buildConstantsContent);
        String sha256 = sha256(jar);
        Path checksum = Path.of(jar + ".sha256");
        Files.writeString(checksum, sha256 + "  " + jar.getFileName() + "\n", StandardCharsets.UTF_8);
        return new Fixture(root, temporary, jar, checksum,
                Path.of(jar + ".manifest.json"), sha256, mavenMarker);
    }

    private static byte[] validBuildConstants() throws IOException {
        try (InputStream input = BuildConstants.class.getResourceAsStream("BuildConstants.class")) {
            assertNotNull(input, "Compiled BuildConstants.class fixture must be available");
            return input.readAllBytes();
        }
    }

    private void writeFixtureJar(
            Path jarPath, String pluginMetadataVersion, byte[] buildConstantsContent) throws IOException {
        try (JarOutputStream jar = new JarOutputStream(Files.newOutputStream(jarPath))) {
            writeJarEntry(jar, "velocity-plugin.json", """
                    {"id":"veloauth","name":"VeloAuth","version":"%s",
                     "main":"net.rafalohaki.veloauth.VeloAuth","dependencies":[]}
                    """.formatted(pluginMetadataVersion).getBytes(StandardCharsets.UTF_8));
            writeJarEntry(jar, POM_PROPERTIES, """
                    artifactId=veloauth
                    groupId=net.rafalohaki.veloauth
                    version=1.5.0
                    """.getBytes(StandardCharsets.ISO_8859_1));
            if (buildConstantsContent != null) {
                writeJarEntry(jar, BUILD_CONSTANTS_CLASS, buildConstantsContent);
            }
        }
    }

    private static void writeJarEntry(JarOutputStream jar, String name, byte[] content) throws IOException {
        jar.putNextEntry(new JarEntry(name));
        jar.write(content);
        jar.closeEntry();
    }

    private VerificationResult runVerifier(Fixture fixture, String expectedTag) throws Exception {
        assertTrue(Files.isExecutable(VERIFIER), "Release identity verifier must exist and be executable");
        ProcessBuilder processBuilder = new ProcessBuilder(VERIFIER.toString(), expectedTag);
        processBuilder.redirectErrorStream(true);
        processBuilder.environment().put("VELOAUTH_RELEASE_IDENTITY_TEST_MODE", "true");
        processBuilder.environment().put("VELOAUTH_RELEASE_IDENTITY_PROJECT_DIR", fixture.root().toString());
        processBuilder.environment().put("TMPDIR", fixture.temporary().toString());
        VerificationResult result = runProcess(processBuilder);
        try (var entries = Files.list(fixture.temporary())) {
            assertEquals(0, entries.count(), "Verifier must clean every task-owned temporary directory");
        }
        return result;
    }

    private static VerificationResult runProcess(ProcessBuilder processBuilder) throws Exception {
        Process process = processBuilder.start();
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        Thread reader = Thread.startVirtualThread(() -> {
            try (InputStream input = process.getInputStream()) {
                input.transferTo(output);
            } catch (IOException e) {
                throw new IllegalStateException(e);
            }
        });
        assertTrue(process.waitFor(10, TimeUnit.SECONDS), "Release verifier process timed out");
        reader.join();
        return new VerificationResult(process.exitValue(), output.toString(StandardCharsets.UTF_8));
    }

    private static String readProjectVersion(Path pom) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(true);
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
        Element project = factory.newDocumentBuilder().parse(pom.toFile()).getDocumentElement();
        for (int index = 0; index < project.getChildNodes().getLength(); index++) {
            if (project.getChildNodes().item(index) instanceof Element element
                    && "version".equals(element.getLocalName())) {
                return element.getTextContent().trim();
            }
        }
        throw new IllegalStateException("Maven project version is missing");
    }

    private static void assertReleaseJarIdentity(Path jarPath, String expectedVersion) throws Exception {
        assertEquals("veloauth-" + expectedVersion + ".jar", jarPath.getFileName().toString(),
                "Release JAR name must use the Maven version");
        try (JarFile jar = new JarFile(jarPath.toFile())) {
            JsonObject metadata;
            try (InputStream input = readJarEntry(jar, "velocity-plugin.json")) {
                metadata = JsonParser.parseReader(
                        new java.io.InputStreamReader(input, StandardCharsets.UTF_8))
                        .getAsJsonObject();
            }
            assertEquals(expectedVersion, metadata.get("version").getAsString(),
                    "Packaged plugin metadata must use the Maven version");

            Properties pomProperties = new Properties();
            try (InputStream input = jar.getInputStream(requiredEntry(jar, POM_PROPERTIES))) {
                pomProperties.load(input);
            }
            assertEquals("net.rafalohaki.veloauth", pomProperties.getProperty("groupId"));
            assertEquals("veloauth", pomProperties.getProperty("artifactId"));
            assertEquals(expectedVersion, pomProperties.getProperty("version"),
                    "Packaged Maven metadata must use the project version");
        }

        try (URLClassLoader loader = new URLClassLoader(
                new java.net.URL[]{jarPath.toUri().toURL()}, ClassLoader.getPlatformClassLoader())) {
            Class<?> artifactConstants = Class.forName(
                    "net.rafalohaki.veloauth.BuildConstants", false, loader);
            assertEquals(loader, artifactConstants.getClassLoader(),
                    "Release metadata must be loaded from the candidate JAR");
            assertEquals(expectedVersion, artifactConstants.getField("VERSION").get(null),
                    "Packaged BuildConstants must use the project version");
        }
    }

    private static InputStream readJarEntry(JarFile jar, String name) throws IOException {
        return jar.getInputStream(requiredEntry(jar, name));
    }

    private static JarEntry requiredEntry(JarFile jar, String name) {
        JarEntry entry = jar.getJarEntry(name);
        assertNotNull(entry, "Release JAR must contain " + name);
        return entry;
    }

    private static String sha256(Path path) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        try (InputStream input = Files.newInputStream(path)) {
            byte[] buffer = new byte[8192];
            int read;
            while ((read = input.read(buffer)) >= 0) {
                digest.update(buffer, 0, read);
            }
        }
        return HexFormat.of().formatHex(digest.digest());
    }

    private record Fixture(
            Path root, Path temporary, Path jar, Path checksum, Path manifest, String sha256,
            Path mavenMarker) {
    }

    private record VerificationResult(int exitCode, String output) {
    }
}
