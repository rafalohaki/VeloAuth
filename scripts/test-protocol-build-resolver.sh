#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
FIXTURE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/veloauth-protocol-resolver-test.XXXXXX")"

cleanup() {
  if [[ -d "${FIXTURE_DIR}" && "$(basename -- "${FIXTURE_DIR}")" == veloauth-protocol-resolver-test.* ]]; then
    rm -rf -- "${FIXTURE_DIR}"
  fi
}
trap cleanup EXIT

VIA_ROOT="${FIXTURE_DIR}/via"
mkdir -p \
  "${VIA_ROOT}/com/viaversion/viaversion-common/6.0.0-SNAPSHOT" \
  "${FIXTURE_DIR}/via-classes/com/viaversion/viaversion" \
  "${FIXTURE_DIR}/via-classes/com/viaversion/viaversion/platform" \
  "${FIXTURE_DIR}/via-classes/com/viaversion/viaversion/protocols/v1_8to1_9"

printf 'fixture' > "${FIXTURE_DIR}/via-classes/com/viaversion/viaversion/ViaManagerImpl.class"
printf 'fixture' > "${FIXTURE_DIR}/via-classes/com/viaversion/viaversion/platform/ViaChannelInitializer.class"
printf 'fixture' > "${FIXTURE_DIR}/via-classes/com/viaversion/viaversion/protocols/v1_8to1_9/Protocol1_8To1_9.class"

jar --create --file \
  "${VIA_ROOT}/com/viaversion/viaversion-common/6.0.0-SNAPSHOT/viaversion-common-6.0.0-20270102.040506-7.jar" \
  -C "${FIXTURE_DIR}/via-classes" .

cat > "${VIA_ROOT}/com/viaversion/viaversion-common/maven-metadata.xml" <<'XML'
<metadata><versioning><latest>6.0.0-SNAPSHOT</latest></versioning></metadata>
XML
cat > "${VIA_ROOT}/com/viaversion/viaversion-common/6.0.0-SNAPSHOT/maven-metadata.xml" <<'XML'
<metadata><versioning><snapshotVersions><snapshotVersion><extension>jar</extension><value>6.0.0-20270102.040506-7</value></snapshotVersion></snapshotVersions></versioning></metadata>
XML

OUTPUT="$(
  VELOAUTH_PROTOCOL_RESOLVER_TEST_MODE=true \
  VIAVERSION_REPOSITORY_URL="file://${VIA_ROOT}" \
  "${SCRIPT_DIR}/build-latest-protocol.sh" --resolve-only
)"

grep -Fqx 'VIAVERSION_DEPENDENCY_VERSION=6.0.0-SNAPSHOT' <<< "${OUTPUT}"
grep -Fqx 'VIAVERSION_RESOLVED_VERSION=6.0.0-20270102.040506-7' <<< "${OUTPUT}"
grep -Eq '^VIAVERSION_SHA256=[0-9a-f]{64}$' <<< "${OUTPUT}"
grep -Fqx "VIAVERSION_URL=file://${VIA_ROOT}/com/viaversion/viaversion-common/6.0.0-SNAPSHOT/viaversion-common-6.0.0-20270102.040506-7.jar" <<< "${OUTPUT}"

echo "Protocol snapshot resolver fixture test passed"
