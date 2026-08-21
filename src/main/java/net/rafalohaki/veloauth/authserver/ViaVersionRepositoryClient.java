package net.rafalohaki.veloauth.authserver;

import org.slf4j.Logger;

import java.net.URI;
import java.net.http.HttpClient;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Objects;

/** Downloads exact, independently pinned ViaVersion artifacts from one allowed repository. */
final class ViaVersionRepositoryClient {

    private static final String HTTPS_SCHEME = "https";

    private static final URI OFFICIAL_REPOSITORY = URI.create(
            "https://repo.viaversion.com/com/viaversion/viaversion-common/");
    private static final Duration CONNECT_TIMEOUT = Duration.ofSeconds(10);

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
        if (requireHttps && !HTTPS_SCHEME.equalsIgnoreCase(uri.getScheme())) {
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

    private void validateRepositoryTransport() {
        if (!repository.isAbsolute() || repository.getHost() == null) {
            throw new IllegalArgumentException("ViaVersion repository must be an absolute URI");
        }
        if (requireHttps && !HTTPS_SCHEME.equalsIgnoreCase(repository.getScheme())) {
            throw new IllegalArgumentException("ViaVersion runtime repository must use HTTPS");
        }
    }

    private static int effectivePort(URI uri) {
        if (uri.getPort() >= 0) {
            return uri.getPort();
        }
        return HTTPS_SCHEME.equalsIgnoreCase(uri.getScheme()) ? 443 : 80;
    }

    private static URI normalizedRepository(URI repository) {
        Objects.requireNonNull(repository, "repository");
        String value = repository.toString();
        return URI.create(value.endsWith("/") ? value : value + '/').normalize();
    }
}
