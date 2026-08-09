package net.rafalohaki.veloauth.authserver;

import org.slf4j.Logger;

import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Locale;
import java.util.Objects;
import java.util.regex.Pattern;

/** Resolves and validates immutable ViaVersion artifacts from one trusted Maven repository. */
final class ViaVersionRepositoryClient {

    private static final URI OFFICIAL_REPOSITORY = URI.create(
            "https://repo.viaversion.com/com/viaversion/viaversion-common/");
    private static final Duration CONNECT_TIMEOUT = Duration.ofSeconds(10);
    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(30);
    private static final int MAXIMUM_METADATA_BYTES = 1024 * 1024;
    private static final int MAXIMUM_CHECKSUM_BYTES = 256;
    private static final Pattern SNAPSHOT_LINE = Pattern.compile(
            "[0-9]+(?:\\.[0-9]+){2,3}-SNAPSHOT");

    private final URI repository;
    private final HttpClient httpClient;
    private final boolean requireHttps;

    private ViaVersionRepositoryClient(
            URI repository,
            HttpClient httpClient,
            boolean requireHttps) {
        this.repository = normalizedRepository(repository);
        this.httpClient = Objects.requireNonNull(httpClient, "httpClient");
        this.requireHttps = requireHttps;
        validateRepositoryTransport();
    }

    static ViaVersionRepositoryClient official() {
        return new ViaVersionRepositoryClient(
                OFFICIAL_REPOSITORY,
                HttpClient.newBuilder()
                        .connectTimeout(CONNECT_TIMEOUT)
                        .followRedirects(HttpClient.Redirect.NEVER)
                        .build(),
                true);
    }

    static ViaVersionRepositoryClient create(
            URI repository,
            HttpClient httpClient,
            boolean requireHttps) {
        return new ViaVersionRepositoryClient(repository, httpClient, requireHttps);
    }

    ResolvedSnapshot latestSnapshot() throws IOException {
        String snapshotLine = latestSnapshotLine();
        String resolvedVersion = resolvedJarVersion(snapshotLine);
        URI artifactUri = repository.resolve(snapshotLine
                + "/viaversion-common-" + resolvedVersion + ".jar");
        validateArtifactTransport(artifactUri);
        return new ResolvedSnapshot(resolvedVersion, artifactUri);
    }

    RuntimeArtifactDescriptor resolveDescriptor(ResolvedSnapshot snapshot) throws IOException {
        Objects.requireNonNull(snapshot, "snapshot");
        String checksum = remoteChecksum(URI.create(snapshot.artifactUri() + ".sha256"));
        return new RuntimeArtifactDescriptor(snapshot.version(), snapshot.artifactUri(), checksum);
    }

    Path resolveArtifact(
            Path runtimeDirectory,
            RuntimeArtifactDescriptor artifact,
            Logger logger) {
        validateArtifactTransport(artifact.uri());
        return new RuntimeArtifactManager(
                runtimeDirectory,
                artifact,
                httpClient,
                logger,
                requireHttps).resolve();
    }

    void validateArtifactTransport(URI uri) {
        if (requireHttps && !"https".equalsIgnoreCase(uri.getScheme())) {
            throw new IllegalStateException("ViaVersion runtime transport must use HTTPS");
        }
        if (!Objects.equals(repository.getScheme(), uri.getScheme())
                || !Objects.equals(repository.getHost(), uri.getHost())
                || effectivePort(repository) != effectivePort(uri)
                || uri.getUserInfo() != null || uri.getQuery() != null || uri.getFragment() != null
                || !uri.normalize().equals(uri)
                || !uri.getPath().startsWith(repository.getPath())) {
            throw new IllegalStateException("ViaVersion runtime URI is outside the configured repository");
        }
    }

    private String latestSnapshotLine() throws IOException {
        byte[] metadata = fetch(repository.resolve("maven-metadata.xml"), MAXIMUM_METADATA_BYTES,
                "application/xml");
        String latest = readElement(metadata, "latest");
        if (!SNAPSHOT_LINE.matcher(latest).matches()) {
            throw new IOException("ViaVersion repository returned an unsafe latest snapshot line");
        }
        return latest;
    }

    private String resolvedJarVersion(String snapshotLine) throws IOException {
        byte[] metadata = fetch(repository.resolve(snapshotLine + "/maven-metadata.xml"),
                MAXIMUM_METADATA_BYTES, "application/xml");
        XMLStreamReader reader = newXmlReader(metadata);
        try {
            boolean inSnapshotVersion = false;
            String extension = null;
            String classifier = null;
            String value = null;
            while (reader.hasNext()) {
                int event = reader.next();
                if (event == XMLStreamConstants.START_ELEMENT) {
                    String element = reader.getLocalName();
                    if ("snapshotVersion".equals(element)) {
                        inSnapshotVersion = true;
                        extension = null;
                        classifier = null;
                        value = null;
                    } else if (inSnapshotVersion && "extension".equals(element)) {
                        extension = reader.getElementText().trim();
                    } else if (inSnapshotVersion && "classifier".equals(element)) {
                        classifier = reader.getElementText().trim();
                    } else if (inSnapshotVersion && "value".equals(element)) {
                        value = reader.getElementText().trim();
                    }
                } else if (event == XMLStreamConstants.END_ELEMENT
                        && "snapshotVersion".equals(reader.getLocalName())) {
                    String snapshotBase = snapshotLine.substring(
                            0, snapshotLine.length() - "-SNAPSHOT".length());
                    if ("jar".equals(extension) && (classifier == null || classifier.isBlank())
                            && value != null && value.matches(
                                    Pattern.quote(snapshotBase) + "-\\d{8}\\.\\d{6}-\\d+")) {
                        return value;
                    }
                    inSnapshotVersion = false;
                }
            }
        } catch (XMLStreamException e) {
            throw new IOException("Unable to parse ViaVersion snapshot metadata", e);
        } finally {
            closeReader(reader);
        }
        throw new IOException("ViaVersion snapshot metadata does not contain an exact JAR version");
    }

    private String remoteChecksum(URI checksumUri) throws IOException {
        String checksum = new String(fetch(checksumUri, MAXIMUM_CHECKSUM_BYTES, "text/plain"),
                StandardCharsets.US_ASCII).trim().toLowerCase(Locale.ROOT);
        if (!checksum.matches("[0-9a-f]{64}")) {
            throw new IOException("ViaVersion repository returned an invalid SHA-256 checksum");
        }
        return checksum;
    }

    private byte[] fetch(URI uri, int maximumBytes, String accept) throws IOException {
        validateArtifactTransport(uri);
        HttpResponse<InputStream> response = RuntimeIo.send(
                httpClient,
                RuntimeIo.request(uri, REQUEST_TIMEOUT, accept),
                "Interrupted while checking ViaVersion snapshot metadata");
        try (InputStream input = response.body()) {
            if (response.statusCode() != 200) {
                throw new IOException("ViaVersion repository returned HTTP " + response.statusCode());
            }
            long declared = response.headers().firstValueAsLong("Content-Length").orElse(-1);
            if (declared > maximumBytes) {
                throw new IOException("ViaVersion repository response exceeds the size limit");
            }
            return readBounded(input, maximumBytes);
        }
    }

    private static byte[] readBounded(InputStream input, int maximumBytes) throws IOException {
        ByteArrayOutputStream output = new ByteArrayOutputStream(Math.min(maximumBytes, 16 * 1024));
        byte[] buffer = new byte[4096];
        int total = 0;
        int read;
        while ((read = input.read(buffer)) != -1) {
            total += read;
            if (total > maximumBytes) {
                throw new IOException("ViaVersion repository response exceeds the size limit");
            }
            output.write(buffer, 0, read);
        }
        return output.toByteArray();
    }

    private static String readElement(byte[] metadata, String target) throws IOException {
        XMLStreamReader reader = newXmlReader(metadata);
        try {
            while (reader.hasNext()) {
                if (reader.next() == XMLStreamConstants.START_ELEMENT
                        && target.equals(reader.getLocalName())) {
                    String value = reader.getElementText().trim();
                    if (!value.isEmpty()) {
                        return value;
                    }
                }
            }
        } catch (XMLStreamException e) {
            throw new IOException("Unable to parse ViaVersion repository metadata", e);
        } finally {
            closeReader(reader);
        }
        throw new IOException("ViaVersion metadata is missing " + target);
    }

    private static XMLStreamReader newXmlReader(byte[] metadata) throws IOException {
        try {
            return xmlInputFactory().createXMLStreamReader(new ByteArrayInputStream(metadata));
        } catch (XMLStreamException e) {
            throw new IOException("Unable to open ViaVersion repository metadata", e);
        }
    }

    private static void closeReader(XMLStreamReader reader) throws IOException {
        try {
            reader.close();
        } catch (XMLStreamException e) {
            throw new IOException("Unable to close ViaVersion repository metadata", e);
        }
    }

    private static XMLInputFactory xmlInputFactory() {
        XMLInputFactory factory = XMLInputFactory.newFactory();
        factory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
        factory.setProperty("javax.xml.stream.isSupportingExternalEntities", false);
        return factory;
    }

    private void validateRepositoryTransport() {
        if (!repository.isAbsolute() || repository.getHost() == null) {
            throw new IllegalArgumentException("ViaVersion repository must be an absolute URI");
        }
        if (requireHttps && !"https".equalsIgnoreCase(repository.getScheme())) {
            throw new IllegalArgumentException("ViaVersion snapshot repository must use HTTPS");
        }
    }

    private static int effectivePort(URI uri) {
        if (uri.getPort() >= 0) {
            return uri.getPort();
        }
        return "https".equalsIgnoreCase(uri.getScheme()) ? 443 : 80;
    }

    private static URI normalizedRepository(URI repository) {
        Objects.requireNonNull(repository, "repository");
        String value = repository.toString();
        return URI.create(value.endsWith("/") ? value : value + '/').normalize();
    }

    record ResolvedSnapshot(String version, URI artifactUri) {
        ResolvedSnapshot {
            Objects.requireNonNull(version, "version");
            Objects.requireNonNull(artifactUri, "artifactUri");
        }
    }
}
