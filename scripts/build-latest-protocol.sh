#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
VIAVERSION_REPOSITORY_URL="${VIAVERSION_REPOSITORY_URL:-https://repo.viaversion.com}"
RESOLVER_TEST_MODE="${VELOAUTH_PROTOCOL_RESOLVER_TEST_MODE:-false}"
RESOLVE_ONLY=false
SKIP_SMOKE=false
MAX_METADATA_BYTES=$((1024 * 1024))
MAX_ARTIFACT_BYTES=$((32 * 1024 * 1024))
WORK_DIR=""

usage() {
  echo "Usage: $0 [--resolve-only] [--skip-smoke]" >&2
  echo "  no option      resolve current snapshots, build, verify and smoke-test" >&2
  echo "  --resolve-only resolve and validate immutable snapshot artifacts only" >&2
  echo "  --skip-smoke   run the complete Maven gate without the real Velocity smoke" >&2
}

for argument in "$@"; do
  case "${argument}" in
    --resolve-only)
      RESOLVE_ONLY=true
      ;;
    --skip-smoke)
      SKIP_SMOKE=true
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      usage
      echo "Unknown option: ${argument}" >&2
      exit 2
      ;;
  esac
done

cleanup() {
  if [[ -n "${WORK_DIR}" && -d "${WORK_DIR}" \
      && "$(basename -- "${WORK_DIR}")" == veloauth-protocol-latest.* ]]; then
    rm -rf -- "${WORK_DIR}"
  fi
}
trap cleanup EXIT

log() {
  printf '%s\n' "$*" >&2
}

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "$1 is required" >&2
    exit 1
  fi
}

require_command curl
require_command jar
require_command python3

WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/veloauth-protocol-latest.XXXXXX")"

normalize_repository_url() {
  local repository_url="${1%/}"
  if [[ "${RESOLVER_TEST_MODE}" == true && "${repository_url}" == file://* ]]; then
    printf '%s\n' "${repository_url}"
    return
  fi
  if [[ "${repository_url}" != https://* ]]; then
    echo "Protocol repositories must use HTTPS" >&2
    exit 1
  fi
  printf '%s\n' "${repository_url}"
}

VIAVERSION_REPOSITORY_URL="$(normalize_repository_url "${VIAVERSION_REPOSITORY_URL}")"

fetch_url() {
  local source_url="$1"
  local destination="$2"
  local maximum_bytes="$3"
  local curl_options=(
    --fail
    --silent
    --show-error
    --connect-timeout 10
    --max-time 60
    --max-filesize "${maximum_bytes}"
    --output "${destination}"
  )
  if [[ "${source_url}" == https://* ]]; then
    curl --proto '=https' --tlsv1.2 "${curl_options[@]}" "${source_url}"
  elif [[ "${RESOLVER_TEST_MODE}" == true && "${source_url}" == file://* ]]; then
    curl "${curl_options[@]}" "${source_url}"
  else
    echo "Refusing non-HTTPS protocol artifact URL: ${source_url}" >&2
    exit 1
  fi

  local downloaded_bytes
  downloaded_bytes="$(wc -c < "${destination}" | tr -d '[:space:]')"
  if [[ ! "${downloaded_bytes}" =~ ^[0-9]+$ \
      || "${downloaded_bytes}" -le 0 \
      || "${downloaded_bytes}" -gt "${maximum_bytes}" ]]; then
    echo "Downloaded artifact has an invalid size: ${source_url}" >&2
    exit 1
  fi
}

xml_value() {
  python3 - "$1" "$2" <<'PY'
import sys
import xml.etree.ElementTree as ET

document = ET.parse(sys.argv[1]).getroot()
mode = sys.argv[2]
if mode == "latest":
    value = document.findtext("./versioning/latest")
elif mode == "snapshot-jar":
    value = None
    for candidate in document.findall("./versioning/snapshotVersions/snapshotVersion"):
        extension = (candidate.findtext("extension") or "").strip()
        classifier = (candidate.findtext("classifier") or "").strip()
        if extension == "jar" and not classifier:
            value = candidate.findtext("value")
            break
else:
    raise SystemExit(f"unsupported XML selector: {mode}")

if value is None or not value.strip():
    raise SystemExit(f"missing {mode} value in Maven metadata")
print(value.strip())
PY
}

validate_snapshot_line() {
  if [[ ! "$1" =~ ^[0-9]+(\.[0-9]+){2,3}-SNAPSHOT$ ]]; then
    echo "Repository returned an unsafe snapshot version: $1" >&2
    exit 1
  fi
}

validate_resolved_version() {
  local resolved_version="$1"
  local snapshot_base="${2%-SNAPSHOT}"
  local escaped_base="${snapshot_base//./\\.}"
  if [[ ! "${resolved_version}" =~ ^${escaped_base}-[0-9]{8}\.[0-9]{6}-[0-9]+$ ]]; then
    echo "Repository returned an unsafe resolved snapshot version: $1" >&2
    exit 1
  fi
}

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    echo "sha256sum or shasum is required" >&2
    exit 1
  fi
}

validate_jar() {
  local artifact="$1"
  shift
  local listing="${WORK_DIR}/$(basename -- "${artifact}").entries"
  if ! jar --list --file "${artifact}" > "${listing}"; then
    echo "Downloaded file is not a readable JAR: ${artifact}" >&2
    exit 1
  fi
  local required_entry
  for required_entry in "$@"; do
    if ! grep -Fqx "${required_entry}" "${listing}"; then
      echo "Downloaded JAR is missing required entry: ${required_entry}" >&2
      exit 1
    fi
  done
}

resolve_protocol_artifacts() {
  local via_group_path="com/viaversion/viaversion-common"
  local via_root_metadata="${WORK_DIR}/via-root-metadata.xml"
  local via_snapshot_metadata="${WORK_DIR}/via-snapshot-metadata.xml"

  fetch_url "${VIAVERSION_REPOSITORY_URL}/${via_group_path}/maven-metadata.xml" \
    "${via_root_metadata}" "${MAX_METADATA_BYTES}"

  VIAVERSION_DEPENDENCY_VERSION="$(xml_value "${via_root_metadata}" latest)"
  validate_snapshot_line "${VIAVERSION_DEPENDENCY_VERSION}"

  fetch_url "${VIAVERSION_REPOSITORY_URL}/${via_group_path}/${VIAVERSION_DEPENDENCY_VERSION}/maven-metadata.xml" \
    "${via_snapshot_metadata}" "${MAX_METADATA_BYTES}"

  VIAVERSION_RESOLVED_VERSION="$(xml_value "${via_snapshot_metadata}" snapshot-jar)"
  validate_resolved_version "${VIAVERSION_RESOLVED_VERSION}" "${VIAVERSION_DEPENDENCY_VERSION}"

  VIAVERSION_URL="${VIAVERSION_REPOSITORY_URL}/${via_group_path}/${VIAVERSION_DEPENDENCY_VERSION}/viaversion-common-${VIAVERSION_RESOLVED_VERSION}.jar"
  VIAVERSION_JAR="${WORK_DIR}/viaversion-common-${VIAVERSION_RESOLVED_VERSION}.jar"

  fetch_url "${VIAVERSION_URL}" "${VIAVERSION_JAR}" "${MAX_ARTIFACT_BYTES}"
  validate_jar "${VIAVERSION_JAR}" \
    "com/viaversion/viaversion/ViaManagerImpl.class" \
    "com/viaversion/viaversion/platform/ViaChannelInitializer.class" \
    "com/viaversion/viaversion/protocols/v1_8to1_9/Protocol1_8To1_9.class"
  VIAVERSION_SHA256="$(sha256_file "${VIAVERSION_JAR}")"
}

resolve_protocol_artifacts

if [[ "${RESOLVE_ONLY}" == true ]]; then
  printf 'VIAVERSION_DEPENDENCY_VERSION=%s\n' "${VIAVERSION_DEPENDENCY_VERSION}"
  printf 'VIAVERSION_RESOLVED_VERSION=%s\n' "${VIAVERSION_RESOLVED_VERSION}"
  printf 'VIAVERSION_SHA256=%s\n' "${VIAVERSION_SHA256}"
  printf 'VIAVERSION_URL=%s\n' "${VIAVERSION_URL}"
  exit 0
fi

if [[ "${RESOLVER_TEST_MODE}" == true ]]; then
  echo "Test repository overrides are permitted only with --resolve-only" >&2
  exit 1
fi

if command -v mvnd >/dev/null 2>&1; then
  MAVEN=(mvnd)
elif [[ -x "${PROJECT_DIR}/mvnw" ]]; then
  MAVEN=("${PROJECT_DIR}/mvnw")
elif command -v mvn >/dev/null 2>&1; then
  MAVEN=(mvn)
else
  echo "Maven, mvnd or ./mvnw is required" >&2
  exit 1
fi

evaluate_maven_expression() {
  "${MAVEN[@]}" -nsu -f "${PROJECT_DIR}/pom.xml" help:evaluate \
    -Dstyle.color=never -DforceStdout -Dexpression="$1" \
    | awk 'NF && $0 !~ /^\[/ { value=$0 } END { print value }'
}

log "Resolved ViaVersion ${VIAVERSION_DEPENDENCY_VERSION} -> ${VIAVERSION_RESOLVED_VERSION}"
log "Verifying the pinned MCProtocolLib transport before using the latest translator"
"${SCRIPT_DIR}/verify-embedded-dependencies.sh"

MCPROTOCOLLIB_DEPENDENCY_VERSION="$(evaluate_maven_expression mcprotocollib.version)"
MCPROTOCOLLIB_RESOLVED_VERSION="$(evaluate_maven_expression mcprotocollib.resolved-version)"
MCPROTOCOLLIB_SHA256="$(evaluate_maven_expression mcprotocollib.sha256)"

log "Priming the exact ViaVersion snapshot line in the local Maven repository"

"${MAVEN[@]}" -B -U -f "${PROJECT_DIR}/pom.xml" dependency:get \
  -Dartifact="com.viaversion:viaversion-common:${VIAVERSION_DEPENDENCY_VERSION}" \
  -Dtransitive=true

LOCAL_REPOSITORY="$(evaluate_maven_expression settings.localRepository)"
LOCAL_VIAVERSION_JAR="${LOCAL_REPOSITORY}/com/viaversion/viaversion-common/${VIAVERSION_DEPENDENCY_VERSION}/viaversion-common-${VIAVERSION_DEPENDENCY_VERSION}.jar"

if [[ ! -f "${LOCAL_VIAVERSION_JAR}" ]]; then
  echo "Maven did not publish the resolved snapshot aliases into the local repository" >&2
  exit 1
fi
if [[ "$(sha256_file "${LOCAL_VIAVERSION_JAR}")" != "${VIAVERSION_SHA256}" ]]; then
  echo "Snapshot metadata changed while resolving dependencies; rerun the build to avoid mixed bytes" >&2
  exit 1
fi

PROJECT_VERSION="$(evaluate_maven_expression project.version)"
OUTPUT_NAME="veloauth-${PROJECT_VERSION}-protocol-latest"
OUTPUT_JAR="${PROJECT_DIR}/target/${OUTPUT_NAME}.jar"

log "Running the complete Maven quality gate against the resolved snapshot bytes"
"${MAVEN[@]}" -B -V -nsu -f "${PROJECT_DIR}/pom.xml" \
  -Dmcprotocollib.resolved-version="${MCPROTOCOLLIB_RESOLVED_VERSION}" \
  -Dmcprotocollib.sha256="${MCPROTOCOLLIB_SHA256}" \
  -Dviaversion.runtime.dependency-version="${VIAVERSION_DEPENDENCY_VERSION}" \
  -Dviaversion.runtime.version="${VIAVERSION_RESOLVED_VERSION}" \
  -Dviaversion.runtime.url="${VIAVERSION_URL}" \
  -Dviaversion.runtime.sha256="${VIAVERSION_SHA256}" \
  -Dembedded.build.channel=protocol-latest \
  -Dbuild.finalName="${OUTPUT_NAME}" \
  clean verify pmd:cpd-check

if [[ ! -f "${OUTPUT_JAR}" ]]; then
  echo "Latest-protocol build did not produce the expected JAR: ${OUTPUT_JAR}" >&2
  exit 1
fi

PROVENANCE_DIR="${WORK_DIR}/provenance"
mkdir -p "${PROVENANCE_DIR}"
(
  cd "${PROVENANCE_DIR}"
  jar --extract --file "${OUTPUT_JAR}" META-INF/veloauth/embedded-runtime.properties
)
PROVENANCE_FILE="${PROVENANCE_DIR}/META-INF/veloauth/embedded-runtime.properties"
grep -Fqx "build.channel=protocol-latest" "${PROVENANCE_FILE}"
grep -Fqx "mcprotocollib.resolved.version=${MCPROTOCOLLIB_RESOLVED_VERSION}" "${PROVENANCE_FILE}"
grep -Fqx "mcprotocollib.sha256=${MCPROTOCOLLIB_SHA256}" "${PROVENANCE_FILE}"
grep -Fqx "viaversion.resolved.version=${VIAVERSION_RESOLVED_VERSION}" "${PROVENANCE_FILE}"
grep -Fqx "viaversion.sha256=${VIAVERSION_SHA256}" "${PROVENANCE_FILE}"

if [[ "${SKIP_SMOKE}" == false ]]; then
  log "Starting a real Velocity smoke test with the exact latest-protocol JAR"
  VELOAUTH_PLUGIN_JAR="${OUTPUT_JAR}" VELOAUTH_TEST_RUNTIME_UPDATE=false \
    "${SCRIPT_DIR}/test-velocity-embedded.sh"
fi

OUTPUT_SHA256="$(sha256_file "${OUTPUT_JAR}")"
printf 'Latest-protocol VeloAuth build passed: %s\n' "${OUTPUT_JAR}"
printf 'JAR_SHA256=%s\n' "${OUTPUT_SHA256}"
printf 'MCPROTOCOLLIB_PINNED=%s (%s)\n' "${MCPROTOCOLLIB_RESOLVED_VERSION}" "${MCPROTOCOLLIB_SHA256}"
printf 'VIAVERSION=%s (%s)\n' "${VIAVERSION_RESOLVED_VERSION}" "${VIAVERSION_SHA256}"
