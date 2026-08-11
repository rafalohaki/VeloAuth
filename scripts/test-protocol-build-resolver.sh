#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
FIXTURE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/veloauth-protocol-resolver-test.XXXXXX")"

cleanup() {
  if [[ -d "${FIXTURE_DIR}" \
      && "$(basename -- "${FIXTURE_DIR}")" == veloauth-protocol-resolver-test.* ]]; then
    rm -rf -- "${FIXTURE_DIR}"
  fi
}
trap cleanup EXIT

ROOT_METADATA="${FIXTURE_DIR}/root-metadata.xml"
SNAPSHOT_METADATA="${FIXTURE_DIR}/snapshot-metadata.xml"

cat >"${ROOT_METADATA}" <<'XML'
<metadata><versioning><latest>6.0.0-SNAPSHOT</latest></versioning></metadata>
XML
cat >"${SNAPSHOT_METADATA}" <<'XML'
<metadata><versioning><snapshotVersions><snapshotVersion><extension>jar</extension><value>6.0.0-20270102.040506-7</value></snapshotVersion></snapshotVersions></versioning></metadata>
XML

OUTPUT="$(
  python3 "${SCRIPT_DIR}/resolve-protocol-metadata.py" \
    --root-metadata "${ROOT_METADATA}" \
    --snapshot-metadata "${SNAPSHOT_METADATA}" \
    --repository-url 'https://fixture.invalid'
)"

grep -Fqx 'VIAVERSION_DEPENDENCY_VERSION=6.0.0-SNAPSHOT' <<<"${OUTPUT}"
grep -Fqx 'VIAVERSION_RESOLVED_VERSION=6.0.0-20270102.040506-7' <<<"${OUTPUT}"
grep -Fqx 'VIAVERSION_URL=https://fixture.invalid/com/viaversion/viaversion-common/6.0.0-SNAPSHOT/viaversion-common-6.0.0-20270102.040506-7.jar' <<<"${OUTPUT}"
if grep -Fq 'VIAVERSION_SHA256=' <<<"${OUTPUT}"; then
  echo "Offline metadata fixture must not derive trust from downloaded artifact bytes" >&2
  exit 1
fi

cat >"${ROOT_METADATA}" <<'XML'
<!DOCTYPE metadata [<!ENTITY remote SYSTEM "https://untrusted.invalid/latest">]>
<metadata><versioning><latest>&remote;</latest></versioning></metadata>
XML
if python3 "${SCRIPT_DIR}/resolve-protocol-metadata.py" \
    --root-metadata "${ROOT_METADATA}" \
    --snapshot-metadata "${SNAPSHOT_METADATA}" \
    --repository-url 'https://fixture.invalid' >/dev/null 2>&1; then
  echo "Offline resolver accepted external XML entities" >&2
  exit 1
fi

if "${SCRIPT_DIR}/build-latest-protocol.sh" --skip-smoke >/dev/null 2>&1; then
  echo "Manual protocol build started without an independently reviewed digest" >&2
  exit 1
fi

echo "Offline protocol metadata resolver fixture passed without downloading bytecode"
