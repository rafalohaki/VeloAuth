#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd -P)"
TEST_MODE="${VELOAUTH_REPRO_TEST_MODE:-false}"
TEMP_PARENT=""
TEMP_PREFIX=""
WORK_DIR=""

PINNED_JAVA_VERSION="21.0.12"
PINNED_JAVA_RUNTIME_PREFIX="21.0.12+8"
PINNED_JAVA_VENDOR="Eclipse Adoptium"
PINNED_JAVA_VENDOR_VERSION="Temurin-21.0.12+8"
PINNED_MAVEN_VERSION="3.9.16"
PINNED_WRAPPER_VERSION="3.3.4"
PINNED_MAVEN_DISTRIBUTION_SHA256="5af3b743dd8b876b5c45da33b676251e5f1687712644abb4ee519ca56e1d89ce"
OFFICIAL_MVNW_SHA256="cae96cef89ebea3531221f4ae17c23cf8edf67d00eae8306d4186ae1bbed4d02"
# Git stores the generated Windows launcher with LF; it is byte-for-byte identical to the
# Wrapper 3.3.4 output after normalizing the generator's CRLF line endings.
OFFICIAL_MVNW_CMD_SHA256="4a361e1374a3e5ad6d03e18e9adc0cf181ac5058ac6203b76f0ba3b456b56481"

fail() {
  echo "$1" >&2
  exit 1
}

cleanup_work_dir() {
  local exit_status=$?
  trap - EXIT
  trap '' HUP INT TERM
  if [[ -z "${WORK_DIR}" ]]; then
    exit "${exit_status}"
  fi

  local temp_suffix="${WORK_DIR#"${TEMP_PREFIX}"}"
  if [[ -z "${TEMP_PREFIX}" || "${WORK_DIR}" != "${TEMP_PREFIX}${temp_suffix}" \
      || ${#temp_suffix} -ne 6 || "${temp_suffix}" == */* || ! -d "${WORK_DIR}" \
      || -L "${WORK_DIR}" || ! -O "${WORK_DIR}" ]]; then
    echo "Refusing to remove unsafe reproducibility temp directory: ${WORK_DIR}" >&2
    [[ ${exit_status} -ne 0 ]] || exit_status=1
    exit "${exit_status}"
  fi

  if ! rm -rf -- "${WORK_DIR}"; then
    echo "Failed to remove reproducibility temp directory: ${WORK_DIR}" >&2
    [[ ${exit_status} -ne 0 ]] || exit_status=1
  fi
  exit "${exit_status}"
}

trap cleanup_work_dir EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

require_command() {
  command -v "$1" >/dev/null 2>&1 || fail "$1 is required"
}

reject_build_environment_overrides() {
  local variable_name variable_value
  for variable_name in \
      MAVEN_ARGS \
      MAVEN_OPTS \
      MAVEN_DEBUG_OPTS \
      JAVA_TOOL_OPTIONS \
      JDK_JAVA_OPTIONS \
      _JAVA_OPTIONS \
      JDK_JAVAC_OPTIONS \
      SOURCE_DATE_EPOCH \
      MAVEN_BASEDIR \
      MAVEN_CONFIG \
      MAVEN_PROJECTBASEDIR \
      MVNW_REPOURL; do
    variable_value="${!variable_name-}"
    [[ -z "${variable_value}" ]] \
      || fail "Build-affecting environment variable must be empty or unset: ${variable_name}"
  done
}

prepare_controlled_maven_files() {
  local owner_dir=$1
  TASK_MAVEN_USER_HOME="${owner_dir}/maven-user-home"
  TASK_MAVEN_SETTINGS="${owner_dir}/maven-settings.xml"
  mkdir -p "${TASK_MAVEN_USER_HOME}"
  (
    umask 077
    printf '%s\n' \
      '<?xml version="1.0" encoding="UTF-8"?>' \
      '<settings xmlns="http://maven.apache.org/SETTINGS/1.2.0"' \
      '          xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"' \
      '          xsi:schemaLocation="http://maven.apache.org/SETTINGS/1.2.0 https://maven.apache.org/xsd/settings-1.2.0.xsd" />' \
      >"${TASK_MAVEN_SETTINGS}"
  )
}

configure_controlled_build_environment() {
  local java_home=${1:-}
  if [[ -n "${java_home}" ]]; then
    export JAVA_HOME="${java_home}"
    export PATH="${JAVA_HOME}/bin:${PATH}"
  fi
  unset MAVEN_ARGS MAVEN_OPTS MAVEN_DEBUG_OPTS JAVA_TOOL_OPTIONS \
    JDK_JAVA_OPTIONS _JAVA_OPTIONS JDK_JAVAC_OPTIONS SOURCE_DATE_EPOCH \
    MAVEN_BASEDIR MAVEN_CONFIG MAVEN_PROJECTBASEDIR MVNW_REPOURL
  export MAVEN_USER_HOME="${TASK_MAVEN_USER_HOME}"
  export MAVEN_SKIP_RC=true
  export VELOAUTH_REPRO_MAVEN_SETTINGS="${TASK_MAVEN_SETTINGS}"
  export TZ=UTC
  export LC_ALL=C
  export LANG=C
}

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    fail "sha256sum or shasum is required"
  fi
}

initialize_work_dir() {
  TEMP_PARENT="$(cd -- "${TMPDIR:-/tmp}" && pwd -P)" \
    || fail "Unable to resolve the temporary directory"
  TEMP_PREFIX="${TEMP_PARENT%/}/veloauth-reproducible."
  WORK_DIR="$(mktemp -d "${TEMP_PREFIX}XXXXXX")" \
    || fail "Unable to create a reproducibility temp directory"
  chmod 700 "${WORK_DIR}" \
    || fail "Unable to make the reproducibility temp directory private"
}

select_candidate() {
  local label=$1
  local build_dir=$2
  local candidates=()
  if [[ -d "${build_dir}/target" ]]; then
    while IFS= read -r candidate; do
      candidates+=("${candidate}")
    done < <(find "${build_dir}/target" -maxdepth 1 -type f \
      -name 'veloauth-*.jar' ! -name 'original-*' -print | LC_ALL=C sort)
  fi
  if [[ ${#candidates[@]} -ne 1 ]]; then
    fail "${label}: expected exactly one non-original target/veloauth-*.jar, found ${#candidates[@]}"
  fi
  printf '%s\n' "${candidates[0]}"
}

diagnose_archive_mismatch() {
  local artifact_a=$1
  local artifact_b=$2
  command -v zipinfo >/dev/null 2>&1 || return 0

  local zipinfo_a="${WORK_DIR:-${TMPDIR:-/tmp}}/zipinfo-a.txt"
  local zipinfo_b="${WORK_DIR:-${TMPDIR:-/tmp}}/zipinfo-b.txt"
  zipinfo -l "${artifact_a}" >"${zipinfo_a}" 2>&1 || true
  zipinfo -l "${artifact_b}" >"${zipinfo_b}" 2>&1 || true
  echo "Bounded zipinfo difference (first 160 lines):" >&2
  diff -u "${zipinfo_a}" "${zipinfo_b}" | sed -n '1,160p' >&2 || true
  if [[ -z "${WORK_DIR}" ]]; then
    rm -f -- "${zipinfo_a}" "${zipinfo_b}"
  fi
}

compare_build_outputs() {
  local build_a=$1
  local build_b=$2
  local expected_name=${3:-}
  local artifact_a artifact_b name_a name_b size_a size_b sha_a sha_b
  artifact_a="$(select_candidate "Build A" "${build_a}")"
  artifact_b="$(select_candidate "Build B" "${build_b}")"
  name_a="$(basename -- "${artifact_a}")"
  name_b="$(basename -- "${artifact_b}")"
  [[ "${name_a}" == "${name_b}" ]] \
    || fail "Artifact name mismatch: build A produced ${name_a}, build B produced ${name_b}"
  if [[ -n "${expected_name}" && "${name_a}" != "${expected_name}" ]]; then
    fail "Artifact name mismatch: expected ${expected_name}, found ${name_a}"
  fi

  size_a="$(wc -c <"${artifact_a}" | tr -d '[:space:]')"
  size_b="$(wc -c <"${artifact_b}" | tr -d '[:space:]')"
  sha_a="$(sha256_file "${artifact_a}")"
  sha_b="$(sha256_file "${artifact_b}")"
  echo "Build A artifact: ${name_a} (${size_a} bytes)"
  echo "Build A SHA-256: ${sha_a}"
  echo "Build B artifact: ${name_b} (${size_b} bytes)"
  echo "Build B SHA-256: ${sha_b}"

  if [[ "${size_a}" != "${size_b}" || "${sha_a}" != "${sha_b}" ]] \
      || ! cmp -s -- "${artifact_a}" "${artifact_b}"; then
    diagnose_archive_mismatch "${artifact_a}" "${artifact_b}"
    fail "Reproducibility verification failed: independently built artifacts differ"
  fi

  echo "Reproducible artifact verified: ${name_a}; SHA-256 ${sha_a}; size ${size_a} bytes"
}

compare_existing_candidate() {
  local candidate=$1
  local build_a=$2
  local build_b=$3
  [[ "${candidate}" == /* ]] \
    || fail "Existing canonical candidate path must be absolute: ${candidate}"
  [[ -f "${candidate}" && ! -L "${candidate}" ]] \
    || fail "Existing canonical candidate must be a regular non-symlink file: ${candidate}"

  local artifact_a artifact_b build_artifact candidate_name build_name candidate_sha build_sha
  artifact_a="$(select_candidate "Build A" "${build_a}")"
  artifact_b="$(select_candidate "Build B" "${build_b}")"
  candidate_name="$(basename -- "${candidate}")"
  for build_artifact in "${artifact_a}" "${artifact_b}"; do
    build_name="$(basename -- "${build_artifact}")"
    [[ "${candidate_name}" == "${build_name}" ]] \
      || fail "Canonical candidate name mismatch: expected ${build_name}, found ${candidate_name}"
  done

  candidate_sha="$(sha256_file "${candidate}")"
  build_sha="$(sha256_file "${artifact_a}")"
  if [[ "$(wc -c <"${candidate}" | tr -d '[:space:]')" \
      != "$(wc -c <"${artifact_a}" | tr -d '[:space:]')" \
      || "${candidate_sha}" != "${build_sha}" ]] \
      || ! cmp -s -- "${candidate}" "${artifact_a}"; then
    diagnose_archive_mismatch "${candidate}" "${artifact_a}"
    fail "Canonical candidate differs from fresh reproducibility Build A"
  fi

  build_sha="$(sha256_file "${artifact_b}")"
  if [[ "$(wc -c <"${candidate}" | tr -d '[:space:]')" \
      != "$(wc -c <"${artifact_b}" | tr -d '[:space:]')" \
      || "${candidate_sha}" != "${build_sha}" ]] \
      || ! cmp -s -- "${candidate}" "${artifact_b}"; then
    diagnose_archive_mismatch "${candidate}" "${artifact_b}"
    fail "Canonical candidate differs from fresh reproducibility Build B"
  fi

  echo "Canonical candidate matches both fresh reproducibility builds: ${candidate_name}; SHA-256 ${candidate_sha}"
}

if [[ $# -gt 0 && ( "$1" == --test-compare || "$1" == --test-compare-existing \
    || "$1" == --test-orchestrate \
    || "$1" == --test-cleanup-probe ) ]]; then
  [[ "${TEST_MODE}" == true ]] \
    || fail "Test-only verifier hooks require VELOAUTH_REPRO_TEST_MODE=true"
  case "$1" in
    --test-compare)
      [[ $# -eq 3 ]] || fail "Usage in test mode: $0 --test-compare BUILD_A BUILD_B"
      initialize_work_dir
      compare_build_outputs "$2" "$3"
      exit 0
      ;;
    --test-compare-existing)
      [[ $# -eq 4 ]] \
        || fail "Usage in test mode: $0 --test-compare-existing CANDIDATE BUILD_A BUILD_B"
      initialize_work_dir
      compare_build_outputs "$3" "$4"
      compare_existing_candidate "$2" "$3" "$4"
      exit 0
      ;;
    --test-orchestrate)
      [[ $# -eq 3 ]] || fail "Usage in test mode: $0 --test-orchestrate BUILDER INVOCATION_LOG"
      [[ -x "$2" ]] || fail "Test builder is not executable: $2"
      initialize_work_dir
      prepare_controlled_maven_files "${WORK_DIR}"
      TEST_BUILD_A="${WORK_DIR}/test-build-a"
      TEST_BUILD_B="${WORK_DIR}/test-build-b"
      mkdir -p "${TEST_BUILD_A}" "${TEST_BUILD_B}"
      (
        configure_controlled_build_environment
        "$2" "${TEST_BUILD_A}" "$3"
        "$2" "${TEST_BUILD_B}" "$3"
      )
      compare_build_outputs "${TEST_BUILD_A}" "${TEST_BUILD_B}"
      exit 0
      ;;
    --test-cleanup-probe)
      [[ $# -eq 1 ]] || fail "Usage in test mode: $0 --test-cleanup-probe"
      initialize_work_dir
      fail "Intentional test-mode failure after verifier temp creation"
      ;;
  esac
fi

[[ "${TEST_MODE}" == false ]] \
  || fail "VELOAUTH_REPRO_TEST_MODE=true is valid only with an explicit test-only hook"
EXISTING_CANDIDATE=""
case $# in
  0) ;;
  2)
    [[ "$1" == --compare-existing ]] || fail "Usage: $0 [--compare-existing ABSOLUTE_JAR]"
    EXISTING_CANDIDATE=$2
    [[ "${EXISTING_CANDIDATE}" == /* ]] \
      || fail "Existing canonical candidate path must be absolute: ${EXISTING_CANDIDATE}"
    [[ -f "${EXISTING_CANDIDATE}" && ! -L "${EXISTING_CANDIDATE}" ]] \
      || fail "Existing canonical candidate must be a regular non-symlink file: ${EXISTING_CANDIDATE}"
    ;;
  *) fail "Usage: $0 [--compare-existing ABSOLUTE_JAR]" ;;
esac
reject_build_environment_overrides

require_command awk
require_command basename
require_command chmod
require_command cmp
require_command diff
require_command find
require_command git
require_command grep
require_command head
require_command mktemp
require_command mkdir
require_command python3
require_command rm
require_command sed
require_command sort
require_command tr
require_command wc

[[ -x "${PROJECT_DIR}/mvnw" ]] || fail "Checked-in ./mvnw is missing or not executable"
[[ -f "${PROJECT_DIR}/mvnw.cmd" ]] || fail "Checked-in mvnw.cmd is missing"
WRAPPER_PROPERTIES="${PROJECT_DIR}/.mvn/wrapper/maven-wrapper.properties"
[[ -f "${WRAPPER_PROPERTIES}" ]] || fail "Missing ${WRAPPER_PROPERTIES}"
[[ ! -e "${PROJECT_DIR}/.mvn/wrapper/maven-wrapper.jar" ]] \
  || fail "only-script Maven Wrapper must not contain maven-wrapper.jar"
grep -Fxq "wrapperVersion=${PINNED_WRAPPER_VERSION}" "${WRAPPER_PROPERTIES}" \
  || fail "Maven Wrapper version must be ${PINNED_WRAPPER_VERSION}"
grep -Fxq "distributionType=only-script" "${WRAPPER_PROPERTIES}" \
  || fail "Maven Wrapper distributionType must be only-script"
grep -Fxq "distributionUrl=https://repo.maven.apache.org/maven2/org/apache/maven/apache-maven/${PINNED_MAVEN_VERSION}/apache-maven-${PINNED_MAVEN_VERSION}-bin.zip" \
  "${WRAPPER_PROPERTIES}" || fail "Maven distribution URL is not the pinned official URL"
grep -Fxq "distributionSha256Sum=${PINNED_MAVEN_DISTRIBUTION_SHA256}" "${WRAPPER_PROPERTIES}" \
  || fail "Maven distribution SHA-256 is missing or incorrect"
[[ "$(sha256_file "${PROJECT_DIR}/mvnw")" == "${OFFICIAL_MVNW_SHA256}" ]] \
  || fail "mvnw differs from the Maven Wrapper ${PINNED_WRAPPER_VERSION} only-script output"
[[ "$(sha256_file "${PROJECT_DIR}/mvnw.cmd")" == "${OFFICIAL_MVNW_CMD_SHA256}" ]] \
  || fail "mvnw.cmd differs from the Maven Wrapper ${PINNED_WRAPPER_VERSION} only-script output"

[[ "$(git -C "${PROJECT_DIR}" rev-parse --is-inside-work-tree 2>/dev/null)" == true ]] \
  || fail "Reproducibility verification requires a Git worktree"
[[ -z "$(git -C "${PROJECT_DIR}" status --porcelain=v1 --untracked-files=normal)" ]] \
  || fail "Reproducibility verification requires a clean Git HEAD"
SOURCE_COMMIT="$(git -C "${PROJECT_DIR}" rev-parse --verify HEAD^{commit})" \
  || fail "Unable to resolve the source commit"

java_home_is_pinned() {
  local candidate=$1
  local metadata java_version java_runtime java_vendor java_vendor_version
  [[ -d "${candidate}" && -x "${candidate}/bin/java" ]] || return 1
  metadata="$("${candidate}/bin/java" -XshowSettings:properties -version 2>&1)" || return 1
  java_version="$(printf '%s\n' "${metadata}" \
    | sed -n 's/^[[:space:]]*java\.version = //p' | head -n 1)"
  java_runtime="$(printf '%s\n' "${metadata}" \
    | sed -n 's/^[[:space:]]*java\.runtime\.version = //p' | head -n 1)"
  java_vendor="$(printf '%s\n' "${metadata}" \
    | sed -n 's/^[[:space:]]*java\.vendor = //p' | head -n 1)"
  java_vendor_version="$(printf '%s\n' "${metadata}" \
    | sed -n 's/^[[:space:]]*java\.vendor\.version = //p' | head -n 1)"
  [[ "${java_version}" == "${PINNED_JAVA_VERSION}" \
      && ( "${java_runtime}" == "${PINNED_JAVA_RUNTIME_PREFIX}" \
        || "${java_runtime}" == "${PINNED_JAVA_RUNTIME_PREFIX}-LTS" ) \
      && "${java_vendor}" == "${PINNED_JAVA_VENDOR}" \
      && "${java_vendor_version}" == "${PINNED_JAVA_VENDOR_VERSION}" ]]
}

PINNED_JAVA_HOME=""
if [[ -n "${VELOAUTH_JAVA21_HOME:-}" ]]; then
  java_home_is_pinned "${VELOAUTH_JAVA21_HOME}" \
    || fail "VELOAUTH_JAVA21_HOME is not exact Temurin ${PINNED_JAVA_VERSION}+8"
  PINNED_JAVA_HOME="$(cd -- "${VELOAUTH_JAVA21_HOME}" && pwd -P)"
else
  JAVA_CANDIDATES=()
  if [[ -x /usr/libexec/java_home ]]; then
    MAC_JAVA_HOME="$(/usr/libexec/java_home -v 21 2>/dev/null || true)"
    [[ -z "${MAC_JAVA_HOME}" ]] || JAVA_CANDIDATES+=("${MAC_JAVA_HOME}")
  fi
  [[ -z "${JAVA_HOME:-}" ]] || JAVA_CANDIDATES+=("${JAVA_HOME}")
  if command -v java >/dev/null 2>&1; then
    PATH_JAVA_METADATA="$(java -XshowSettings:properties -version 2>&1 || true)"
    PATH_JAVA_HOME="$(printf '%s\n' "${PATH_JAVA_METADATA}" \
      | sed -n 's/^[[:space:]]*java\.home = //p' | head -n 1)"
    [[ -z "${PATH_JAVA_HOME}" ]] || JAVA_CANDIDATES+=("${PATH_JAVA_HOME}")
  fi
  for candidate in "${JAVA_CANDIDATES[@]}"; do
    if java_home_is_pinned "${candidate}"; then
      PINNED_JAVA_HOME="$(cd -- "${candidate}" && pwd -P)"
      break
    fi
  done
fi
[[ -n "${PINNED_JAVA_HOME}" ]] \
  || fail "Exact Temurin ${PINNED_JAVA_VERSION}+8 was not found; set VELOAUTH_JAVA21_HOME"

initialize_work_dir
CLONE_A="${WORK_DIR}/source-a"
CLONE_B="${WORK_DIR}/source-b"
REPO_A="${WORK_DIR}/repository-a"
REPO_B="${WORK_DIR}/repository-b"
prepare_controlled_maven_files "${WORK_DIR}"
mkdir -p "${REPO_A}" "${REPO_B}"

git clone --quiet --local --no-hardlinks --no-checkout "${PROJECT_DIR}" "${CLONE_A}"
git clone --quiet --local --no-hardlinks --no-checkout "${PROJECT_DIR}" "${CLONE_B}"
git -C "${CLONE_A}" checkout --quiet --detach "${SOURCE_COMMIT}"
git -C "${CLONE_B}" checkout --quiet --detach "${SOURCE_COMMIT}"
[[ "$(git -C "${CLONE_A}" rev-parse HEAD)" == "${SOURCE_COMMIT}" \
    && "$(git -C "${CLONE_B}" rev-parse HEAD)" == "${SOURCE_COMMIT}" ]] \
  || fail "Isolated clones did not resolve the same source commit"

echo "Reproducibility source commit: ${SOURCE_COMMIT}"
echo "Pinned Java runtime:"
"${PINNED_JAVA_HOME}/bin/java" -version

run_build() {
  local clone_dir=$1
  local repository=$2
  (
    cd -- "${clone_dir}"
    configure_controlled_build_environment "${PINNED_JAVA_HOME}"
    ./mvnw -B -ntp -s "${VELOAUTH_REPRO_MAVEN_SETTINGS}" \
      -Dmaven.repo.local="${repository}" clean package -DskipTests
  )
}

run_build "${CLONE_A}" "${REPO_A}"
run_build "${CLONE_B}" "${REPO_B}"
PROJECT_VERSION="$(python3 - "${CLONE_A}/pom.xml" <<'PY'
import sys
import xml.etree.ElementTree as ElementTree

try:
    root = ElementTree.parse(sys.argv[1]).getroot()
    namespace = root.tag.rpartition("}")[0] + "}" if "}" in root.tag else ""
    version = root.findtext(f"{namespace}version", "").strip()
except (ElementTree.ParseError, OSError) as error:
    print(f"Unable to read Maven project version: {error}", file=sys.stderr)
    raise SystemExit(1)
if not version:
    print("Maven project version is empty", file=sys.stderr)
    raise SystemExit(1)
print(version)
PY
)" || fail "Unable to resolve the Maven project version"
compare_build_outputs "${CLONE_A}" "${CLONE_B}" "veloauth-${PROJECT_VERSION}.jar"
if [[ -n "${EXISTING_CANDIDATE}" ]]; then
  compare_existing_candidate "${EXISTING_CANDIDATE}" "${CLONE_A}" "${CLONE_B}"
fi
