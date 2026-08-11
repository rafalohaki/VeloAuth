#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
DEFAULT_PROJECT_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
TEST_MODE="${VELOAUTH_RELEASE_IDENTITY_TEST_MODE:-false}"
PROJECT_OVERRIDE="${VELOAUTH_RELEASE_IDENTITY_PROJECT_DIR:-}"
MAVEN_OVERRIDE="${VELOAUTH_RELEASE_IDENTITY_MAVEN:-}"
TEMP_PARENT=""
TEMP_PREFIX=""
TEMP_DIR=""

fail() {
  echo "$1" >&2
  exit 1
}

cleanup_temp_dir() {
  local exit_status=$?
  trap - EXIT
  trap '' HUP INT TERM
  if [[ -z "${TEMP_DIR}" ]]; then
    exit "${exit_status}"
  fi

  local temp_suffix="${TEMP_DIR#"${TEMP_PREFIX}"}"
  if [[ -z "${TEMP_PREFIX}" || "${TEMP_DIR}" != "${TEMP_PREFIX}${temp_suffix}" \
      || ${#temp_suffix} -ne 6 || "${temp_suffix}" == */* || ! -d "${TEMP_DIR}" \
      || -L "${TEMP_DIR}" || ! -O "${TEMP_DIR}" ]]; then
    echo "Refusing to remove unsafe release identity temp directory: ${TEMP_DIR}" >&2
    [[ ${exit_status} -ne 0 ]] || exit_status=1
    exit "${exit_status}"
  fi

  if ! rm -rf -- "${TEMP_DIR}"; then
    echo "Failed to remove release identity temp directory: ${TEMP_DIR}" >&2
    [[ ${exit_status} -ne 0 ]] || exit_status=1
  fi
  exit "${exit_status}"
}

trap cleanup_temp_dir EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

if [[ "${TEST_MODE}" != true && ( -n "${PROJECT_OVERRIDE}" || -n "${MAVEN_OVERRIDE}" ) ]]; then
  fail "Test-only release identity overrides require VELOAUTH_RELEASE_IDENTITY_TEST_MODE=true"
fi

if [[ "${TEST_MODE}" == true ]]; then
  [[ -n "${PROJECT_OVERRIDE}" ]] || fail "Test mode requires VELOAUTH_RELEASE_IDENTITY_PROJECT_DIR"
  [[ -n "${MAVEN_OVERRIDE}" ]] || fail "Test mode requires VELOAUTH_RELEASE_IDENTITY_MAVEN"
  [[ -x "${MAVEN_OVERRIDE}" ]] || fail "Test Maven command is not executable: ${MAVEN_OVERRIDE}"
  PROJECT_DIR="$(cd -- "${PROJECT_OVERRIDE}" && pwd)"
  MAVEN=("${MAVEN_OVERRIDE}")
else
  PROJECT_DIR="${DEFAULT_PROJECT_DIR}"
  if [[ -x "${PROJECT_DIR}/mvnw" ]]; then
    MAVEN=("${PROJECT_DIR}/mvnw")
  elif command -v mvnd >/dev/null 2>&1; then
    MAVEN=(mvnd)
  elif command -v mvn >/dev/null 2>&1; then
    MAVEN=(mvn)
  else
    fail "Maven, mvnd or ./mvnw is required"
  fi
fi

[[ $# -le 2 ]] || fail "Usage: $0 [expected-tag] [absolute-candidate-jar]"
EXPECTED_TAG="${1:-}"
CANDIDATE_OVERRIDE="${2:-}"
[[ -f "${PROJECT_DIR}/pom.xml" ]] || fail "Missing Maven project: ${PROJECT_DIR}/pom.xml"

IDENTITY_MAVEN_SETTINGS="${VELOAUTH_RELEASE_IDENTITY_MAVEN_SETTINGS:-}"
IDENTITY_MAVEN_REPOSITORY="${VELOAUTH_RELEASE_IDENTITY_MAVEN_REPOSITORY:-}"
if [[ -n "${IDENTITY_MAVEN_SETTINGS}" || -n "${IDENTITY_MAVEN_REPOSITORY}" ]]; then
  [[ "${IDENTITY_MAVEN_SETTINGS}" == /* && -f "${IDENTITY_MAVEN_SETTINGS}" \
      && ! -L "${IDENTITY_MAVEN_SETTINGS}" ]] \
    || fail "Release identity Maven settings must be an absolute regular non-symlink file"
  [[ "${IDENTITY_MAVEN_REPOSITORY}" == /* && -d "${IDENTITY_MAVEN_REPOSITORY}" \
      && ! -L "${IDENTITY_MAVEN_REPOSITORY}" ]] \
    || fail "Release identity Maven repository must be an absolute real directory"
  MAVEN+=(-s "${IDENTITY_MAVEN_SETTINGS}" \
    "-Dmaven.repo.local=${IDENTITY_MAVEN_REPOSITORY}")
fi

require_command() {
  command -v "$1" >/dev/null 2>&1 || fail "$1 is required"
}

require_command awk
require_command chmod
require_command find
require_command javap
require_command mktemp
require_command python3
require_command rm

MAVEN_OUTPUT="$(
  "${MAVEN[@]}" -f "${PROJECT_DIR}/pom.xml" help:evaluate \
    -Dstyle.color=never -DforceStdout -Dexpression=project.version
)" || fail "Failed to evaluate the Maven project version"
PROJECT_VERSION="$(
  printf '%s\n' "${MAVEN_OUTPUT}" \
    | awk 'NF && $0 !~ /^\[/ { value=$0 } END { print value }'
)"
[[ "${PROJECT_VERSION}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] \
  || fail "Maven project version is not a release version: ${PROJECT_VERSION:-<empty>}"

if [[ -n "${EXPECTED_TAG}" && "${EXPECTED_TAG}" != "v${PROJECT_VERSION}" ]]; then
  fail "Release tag mismatch: expected v${PROJECT_VERSION}, found ${EXPECTED_TAG}"
fi

TARGET_DIR="${PROJECT_DIR}/target"
CANDIDATE_JARS=()
if [[ -n "${CANDIDATE_OVERRIDE}" ]]; then
  [[ "${CANDIDATE_OVERRIDE}" == /* && -f "${CANDIDATE_OVERRIDE}" \
      && ! -L "${CANDIDATE_OVERRIDE}" ]] \
    || fail "Release candidate override must be an absolute regular non-symlink file"
  CANDIDATE_JARS+=("${CANDIDATE_OVERRIDE}")
elif [[ -d "${TARGET_DIR}" ]]; then
  while IFS= read -r candidate; do
    CANDIDATE_JARS+=("${candidate}")
  done < <(find "${TARGET_DIR}" -maxdepth 1 -type f -name 'veloauth-*.jar' -print | sort)
fi

if [[ ${#CANDIDATE_JARS[@]} -ne 1 ]]; then
  fail "Expected exactly one target/veloauth-*.jar, found ${#CANDIDATE_JARS[@]}"
fi

CANDIDATE_JAR="${CANDIDATE_JARS[0]}"
EXPECTED_JAR_NAME="veloauth-${PROJECT_VERSION}.jar"
ACTUAL_JAR_NAME="$(basename -- "${CANDIDATE_JAR}")"
if [[ "${ACTUAL_JAR_NAME}" != "${EXPECTED_JAR_NAME}" ]]; then
  fail "Release JAR name mismatch: expected ${EXPECTED_JAR_NAME}, found ${ACTUAL_JAR_NAME}"
fi

ARTIFACT_METADATA="$(python3 - "${CANDIDATE_JAR}" <<'PY'
import json
import sys
import zipfile

artifact = sys.argv[1]
try:
    with zipfile.ZipFile(artifact) as archive:
        plugin = json.loads(archive.read("velocity-plugin.json"))
        raw_properties = archive.read(
            "META-INF/maven/net.rafalohaki.veloauth/veloauth/pom.properties"
        ).decode("ISO-8859-1")
except (KeyError, OSError, UnicodeDecodeError, ValueError, zipfile.BadZipFile) as error:
    print(f"Unreadable release JAR metadata: {error}", file=sys.stderr)
    raise SystemExit(1)

properties = {}
for raw_line in raw_properties.splitlines():
    line = raw_line.strip()
    if not line or line.startswith(("#", "!")):
        continue
    key, separator, value = line.partition("=")
    if not separator:
        print(f"Malformed Maven metadata line: {raw_line}", file=sys.stderr)
        raise SystemExit(1)
    properties[key.strip()] = value.strip()

print(plugin.get("version", ""))
print(properties.get("groupId", ""))
print(properties.get("artifactId", ""))
print(properties.get("version", ""))
PY
)" || fail "Failed to inspect release JAR metadata"

PLUGIN_VERSION="$(printf '%s\n' "${ARTIFACT_METADATA}" | sed -n '1p')"
POM_GROUP="$(printf '%s\n' "${ARTIFACT_METADATA}" | sed -n '2p')"
POM_ARTIFACT="$(printf '%s\n' "${ARTIFACT_METADATA}" | sed -n '3p')"
POM_VERSION="$(printf '%s\n' "${ARTIFACT_METADATA}" | sed -n '4p')"

[[ "${PLUGIN_VERSION}" == "${PROJECT_VERSION}" ]] \
  || fail "velocity-plugin.json version mismatch: expected ${PROJECT_VERSION}, found ${PLUGIN_VERSION:-<empty>}"
[[ "${POM_GROUP}" == "net.rafalohaki.veloauth" ]] \
  || fail "Packaged Maven groupId mismatch: expected net.rafalohaki.veloauth, found ${POM_GROUP:-<empty>}"
[[ "${POM_ARTIFACT}" == "veloauth" ]] \
  || fail "Packaged Maven artifactId mismatch: expected veloauth, found ${POM_ARTIFACT:-<empty>}"
[[ "${POM_VERSION}" == "${PROJECT_VERSION}" ]] \
  || fail "Packaged Maven version mismatch: expected ${PROJECT_VERSION}, found ${POM_VERSION:-<empty>}"

TEMP_PARENT="$(cd -- "${TMPDIR:-/tmp}" && pwd -P)" \
  || fail "Unable to resolve the temporary directory"
TEMP_PREFIX="${TEMP_PARENT%/}/veloauth-release-identity."
TEMP_DIR="$(mktemp -d "${TEMP_PREFIX}XXXXXX")" \
  || fail "Unable to create a release identity temp directory"
chmod 700 "${TEMP_DIR}" || fail "Unable to make the release identity temp directory private"
BUILD_CONSTANTS_FILE="${TEMP_DIR}/BuildConstants.class"
python3 - "${CANDIDATE_JAR}" "${BUILD_CONSTANTS_FILE}" <<'PY' \
  || fail "Failed to inspect packaged BuildConstants"
import sys
import zipfile

artifact = sys.argv[1]
target = sys.argv[2]
entry_name = "net/rafalohaki/veloauth/BuildConstants.class"
try:
    with zipfile.ZipFile(artifact) as archive:
        entries = [entry for entry in archive.infolist() if entry.filename == entry_name]
        if len(entries) != 1 or entries[0].is_dir():
            raise ValueError(f"expected exactly one file entry named {entry_name}")
        if not 0 < entries[0].file_size <= 1_048_576:
            raise ValueError(f"invalid {entry_name} size")
        content = archive.read(entries[0])
    with open(target, "xb") as stream:
        stream.write(content)
except (OSError, ValueError, zipfile.BadZipFile) as error:
    print(f"Unreadable packaged BuildConstants: {error}", file=sys.stderr)
    raise SystemExit(1)
PY

JAVAP_OUTPUT="$(
  javap -constants "${BUILD_CONSTANTS_FILE}"
)" || fail "Failed to inspect packaged BuildConstants"
BUILD_CONSTANTS_VERSION="$(
  printf '%s\n' "${JAVAP_OUTPUT}" \
    | sed -n 's/^  public static final java\.lang\.String VERSION = "\([^"]*\)";$/\1/p'
)"
[[ "${BUILD_CONSTANTS_VERSION}" == "${PROJECT_VERSION}" ]] \
  || fail "BuildConstants.VERSION mismatch: expected ${PROJECT_VERSION}, found ${BUILD_CONSTANTS_VERSION:-<empty>}"

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    fail "sha256sum or shasum is required"
  fi
}

CHECKSUM_FILE="${CANDIDATE_JAR}.sha256"
[[ -f "${CHECKSUM_FILE}" ]] || fail "Missing release checksum: $(basename -- "${CHECKSUM_FILE}")"
CHECKSUM_RECORDS="$(awk 'NF { count++ } END { print count + 0 }' "${CHECKSUM_FILE}")"
[[ "${CHECKSUM_RECORDS}" == 1 ]] \
  || fail "Malformed release checksum: expected one nonblank record"
CHECKSUM_FIELDS="$(awk 'NF { print NF; exit }' "${CHECKSUM_FILE}")"
[[ "${CHECKSUM_FIELDS}" == 1 || "${CHECKSUM_FIELDS}" == 2 ]] \
  || fail "Malformed release checksum: $(basename -- "${CHECKSUM_FILE}")"
RECORDED_SHA256="$(awk 'NF { print tolower($1); exit }' "${CHECKSUM_FILE}")"
[[ "${RECORDED_SHA256}" =~ ^[0-9a-f]{64}$ ]] \
  || fail "Malformed release checksum: $(basename -- "${CHECKSUM_FILE}")"
if [[ "${CHECKSUM_FIELDS}" == 2 ]]; then
  RECORDED_NAME="$(awk 'NF { print $2; exit }' "${CHECKSUM_FILE}")"
  RECORDED_NAME="${RECORDED_NAME#\*}"
  [[ "${RECORDED_NAME}" == "${ACTUAL_JAR_NAME}" ]] \
    || fail "Release checksum artifact mismatch: expected ${ACTUAL_JAR_NAME}, found ${RECORDED_NAME}"
fi
ACTUAL_SHA256="$(sha256_file "${CANDIDATE_JAR}")"
[[ "${RECORDED_SHA256}" == "${ACTUAL_SHA256}" ]] \
  || fail "Release checksum mismatch: expected ${RECORDED_SHA256}, found ${ACTUAL_SHA256}"

MANIFEST_FILE="${CANDIDATE_JAR}.manifest.json"
MANIFEST_PRODUCER="${PROJECT_DIR}/scripts/create-release-manifest.sh"
MANIFEST_STATUS="not-required"
if [[ -e "${MANIFEST_FILE}" || -e "${MANIFEST_PRODUCER}" ]]; then
  [[ -f "${MANIFEST_FILE}" ]] || fail "Missing release manifest: $(basename -- "${MANIFEST_FILE}")"
  MANIFEST_METADATA="$(python3 - "${MANIFEST_FILE}" <<'PY'
import json
import sys

try:
    with open(sys.argv[1], encoding="utf-8") as stream:
        manifest = json.load(stream)
except (OSError, UnicodeDecodeError, ValueError) as error:
    print(f"Unreadable release manifest: {error}", file=sys.stderr)
    raise SystemExit(1)

print(manifest.get("artifact", ""))
print(manifest.get("version", ""))
print(manifest.get("sha256", ""))
PY
)" || fail "Failed to inspect release manifest"
  MANIFEST_ARTIFACT="$(printf '%s\n' "${MANIFEST_METADATA}" | sed -n '1p')"
  MANIFEST_VERSION="$(printf '%s\n' "${MANIFEST_METADATA}" | sed -n '2p')"
  MANIFEST_SHA256="$(printf '%s\n' "${MANIFEST_METADATA}" | sed -n '3p' | tr '[:upper:]' '[:lower:]')"
  [[ "${MANIFEST_ARTIFACT}" == "${ACTUAL_JAR_NAME}" ]] \
    || fail "Release manifest artifact mismatch: expected ${ACTUAL_JAR_NAME}, found ${MANIFEST_ARTIFACT:-<empty>}"
  [[ "${MANIFEST_VERSION}" == "${PROJECT_VERSION}" ]] \
    || fail "Release manifest version mismatch: expected ${PROJECT_VERSION}, found ${MANIFEST_VERSION:-<empty>}"
  [[ "${MANIFEST_SHA256}" == "${ACTUAL_SHA256}" ]] \
    || fail "Release manifest checksum mismatch: expected ${ACTUAL_SHA256}, found ${MANIFEST_SHA256:-<empty>}"
  MANIFEST_STATUS="verified"
fi

DISPLAY_TAG="${EXPECTED_TAG:-v${PROJECT_VERSION}}"
echo "Verified release identity ${PROJECT_VERSION} (${DISPLAY_TAG}): ${ACTUAL_JAR_NAME}; SHA-256 ${ACTUAL_SHA256}; manifest ${MANIFEST_STATUS}"
