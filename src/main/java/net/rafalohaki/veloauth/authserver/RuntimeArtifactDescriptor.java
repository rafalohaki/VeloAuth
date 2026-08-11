package net.rafalohaki.veloauth.authserver;

import net.rafalohaki.veloauth.BuildConstants;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Immutable identity and verification material for one exact ViaVersion runtime. */
record RuntimeArtifactDescriptor(String version, URI uri, String sha256) {

    private static final Pattern STABLE_VERSION = Pattern.compile(
            "^(\\d+(?:\\.\\d+){2,3})$");
    private static final Pattern TIMESTAMPED_SNAPSHOT = Pattern.compile(
            "^(\\d+(?:\\.\\d+){2,3})-(\\d{8}\\.\\d{6})-(\\d+)$");

    RuntimeArtifactDescriptor {
        Objects.requireNonNull(version, "version");
        Objects.requireNonNull(uri, "uri");
        Objects.requireNonNull(sha256, "sha256");
        if (!version.matches("[0-9][0-9A-Za-z._-]{0,127}")) {
            throw new IllegalArgumentException("Unsafe ViaVersion runtime version");
        }
        if (!uri.isAbsolute() || uri.getHost() == null || uri.getHost().isBlank()) {
            throw new IllegalArgumentException("ViaVersion runtime URI must be absolute and contain a host");
        }
        sha256 = sha256.trim().toLowerCase(Locale.ROOT);
        if (!sha256.matches("[0-9a-f]{64}")) {
            throw new IllegalArgumentException("ViaVersion runtime checksum must be SHA-256");
        }
    }

    static RuntimeArtifactDescriptor pinned() {
        return new RuntimeArtifactDescriptor(
                BuildConstants.EMBEDDED_VIAVERSION_VERSION,
                URI.create(BuildConstants.EMBEDDED_VIAVERSION_URL),
                BuildConstants.EMBEDDED_VIAVERSION_SHA256);
    }

    static RuntimeArtifactDescriptor reviewed() {
        return new RuntimeArtifactDescriptor(
                BuildConstants.REVIEWED_VIAVERSION_VERSION,
                URI.create(BuildConstants.REVIEWED_VIAVERSION_URL),
                BuildConstants.REVIEWED_VIAVERSION_SHA256);
    }

    String artifactName() {
        return "viaversion-common-" + version + ".jar";
    }

    static boolean isNewerVersion(String candidateVersion, String currentVersion) {
        Objects.requireNonNull(candidateVersion, "candidateVersion");
        Objects.requireNonNull(currentVersion, "currentVersion");
        if (candidateVersion.equals(currentVersion)) {
            return false;
        }
        Optional<VersionKey> candidate = VersionKey.parse(candidateVersion);
        Optional<VersionKey> current = VersionKey.parse(currentVersion);
        if (candidate.isEmpty() || current.isEmpty()) {
            return false;
        }
        return candidate.get().compareTo(current.get()) > 0;
    }

    private record VersionKey(
            List<Integer> releaseParts,
            String snapshotTimestamp,
            int snapshotBuild) implements Comparable<VersionKey> {

        private VersionKey {
            releaseParts = List.copyOf(releaseParts);
        }

        private static Optional<VersionKey> parse(String value) {
            Matcher timestamped = TIMESTAMPED_SNAPSHOT.matcher(value);
            try {
                if (timestamped.matches()) {
                    return Optional.of(new VersionKey(
                            parseRelease(timestamped.group(1)),
                            timestamped.group(2),
                            Integer.parseInt(timestamped.group(3))));
                }
                Matcher stable = STABLE_VERSION.matcher(value);
                if (stable.matches()) {
                    return Optional.of(new VersionKey(
                            parseRelease(stable.group(1)),
                            null,
                            0));
                }
            } catch (NumberFormatException invalidVersion) {
                return Optional.empty();
            }
            return Optional.empty();
        }

        private static List<Integer> parseRelease(String value) {
            String[] components = value.split("\\.");
            List<Integer> parsed = new ArrayList<>(components.length);
            for (String component : components) {
                parsed.add(Integer.parseInt(component));
            }
            return parsed;
        }

        @Override
        public int compareTo(VersionKey other) {
            int releaseComparison = compareRelease(other);
            if (releaseComparison != 0) {
                return releaseComparison;
            }
            if (snapshotTimestamp == null) {
                return other.snapshotTimestamp == null ? 0 : 1;
            }
            if (other.snapshotTimestamp == null) {
                return -1;
            }
            int timestampComparison = snapshotTimestamp.compareTo(other.snapshotTimestamp);
            return timestampComparison != 0
                    ? timestampComparison
                    : Integer.compare(snapshotBuild, other.snapshotBuild);
        }

        private int compareRelease(VersionKey other) {
            int components = Math.max(releaseParts.size(), other.releaseParts.size());
            for (int index = 0; index < components; index++) {
                int current = index < releaseParts.size() ? releaseParts.get(index) : 0;
                int compared = index < other.releaseParts.size() ? other.releaseParts.get(index) : 0;
                int comparison = Integer.compare(current, compared);
                if (comparison != 0) {
                    return comparison;
                }
            }
            return 0;
        }
    }
}
