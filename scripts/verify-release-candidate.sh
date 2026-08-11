#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd -P)"
MANIFEST_CREATOR="${SCRIPT_DIR}/create-release-manifest.sh"
TEST_MODE="${VELOAUTH_RELEASE_ARTIFACT_TEST_MODE:-false}"

BUILD_COMMAND="./mvnw -B -V clean verify pmd:cpd-check -DskipTests=false"
JDK_IDENTITY="Eclipse Temurin 21.0.12+8"
MAVEN_IDENTITY="Apache Maven 3.9.16"
REPOSITORY="rafalohaki/VeloAuth"

PINNED_JAVA_VERSION="21.0.12"
PINNED_JAVA_RUNTIME_PREFIX="21.0.12+8"
PINNED_JAVA_VENDOR="Eclipse Adoptium"
PINNED_JAVA_VENDOR_VERSION="Temurin-21.0.12+8"
PINNED_MAVEN_VERSION="3.9.16"

TEMP_PARENT=""
TEMP_PREFIX=""
WORK_DIR=""
TASK_MAVEN_USER_HOME=""
TASK_MAVEN_SETTINGS=""
TASK_MAVEN_REPOSITORY=""

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

  local suffix="${WORK_DIR#"${TEMP_PREFIX}"}"
  if [[ -z "${TEMP_PREFIX}" || "${WORK_DIR}" != "${TEMP_PREFIX}${suffix}" \
      || ${#suffix} -ne 6 || "${suffix}" == */* || ! -d "${WORK_DIR}" \
      || -L "${WORK_DIR}" || ! -O "${WORK_DIR}" ]]; then
    echo "Refusing to remove unsafe release-candidate temp directory: ${WORK_DIR}" >&2
    [[ ${exit_status} -ne 0 ]] || exit_status=1
    exit "${exit_status}"
  fi
  if ! rm -rf -- "${WORK_DIR}"; then
    echo "Failed to remove release-candidate temp directory: ${WORK_DIR}" >&2
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

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    fail "sha256sum or shasum is required"
  fi
}

load_project_metadata() {
  local metadata
  metadata="$(python3 - "${PROJECT_DIR}/pom.xml" <<'PY'
import sys
import xml.etree.ElementTree as ElementTree

try:
    root = ElementTree.parse(sys.argv[1]).getroot()
except (OSError, ElementTree.ParseError) as error:
    print(f"Unable to read Maven project metadata: {error}", file=sys.stderr)
    raise SystemExit(1)
namespace = root.tag.rpartition("}")[0] + "}" if "}" in root.tag else ""
version = (root.findtext(f"{namespace}version") or "").strip()
properties = root.find(f"{namespace}properties")
timestamp = "" if properties is None else (
    properties.findtext(f"{namespace}project.build.outputTimestamp") or ""
).strip()
print(version)
print(timestamp)
PY
)" || fail "Unable to derive release metadata from pom.xml"
  VERSION="$(printf '%s\n' "${metadata}" | sed -n '1p')"
  OUTPUT_TIMESTAMP="$(printf '%s\n' "${metadata}" | sed -n '2p')"
  [[ "${VERSION}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] \
    || fail "Maven project version is not a release version: ${VERSION:-<empty>}"
  [[ "${OUTPUT_TIMESTAMP}" == "2026-08-11T00:00:00Z" ]] \
    || fail "Unexpected project.build.outputTimestamp: ${OUTPUT_TIMESTAMP:-<empty>}"
  ARTIFACT_NAME="veloauth-${VERSION}.jar"
  TAG="v${VERSION}"
  EXPECTED_REF="refs/tags/${TAG}"
  EXPECTED_WORKFLOW="${REPOSITORY}/.github/workflows/build-and-release.yml@${EXPECTED_REF}"
}

render_release_notes() {
  [[ $# -eq 4 ]] \
    || fail "Usage: $0 --render-notes TEMPLATE CHANGELOG OUTPUT VERSION"
  local template=$1
  local changelog=$2
  local output=$3
  local version=$4
  [[ "${template}" == /* && "${changelog}" == /* && "${output}" == /* ]] \
    || fail "Release-note paths must be absolute"
  [[ -f "${template}" && ! -L "${template}" ]] || fail "Release-note template is invalid: ${template}"
  [[ -f "${changelog}" && ! -L "${changelog}" ]] || fail "Release changelog is invalid: ${changelog}"
  [[ "${version}" == "${VERSION}" ]] \
    || fail "Release-note version must be ${VERSION}, found ${version}"
  [[ ! -e "${output}" ]] || fail "Release-note output already exists: ${output}"
  python3 - "${template}" "${changelog}" "${output}" "${version}" <<'PY'
import pathlib
import re
import sys

template_path = pathlib.Path(sys.argv[1])
changelog_path = pathlib.Path(sys.argv[2])
output_path = pathlib.Path(sys.argv[3])
version = sys.argv[4]
try:
    template = template_path.read_text(encoding="utf-8")
    changelog = changelog_path.read_text(encoding="utf-8").rstrip("\n")
except (OSError, UnicodeDecodeError) as error:
    print(f"Unable to read release-note input: {error}", file=sys.stderr)
    raise SystemExit(1)

if template.count("{{VERSION}}") == 0 or template.count("{{CHANGELOG}}") != 1:
    print("Release-note template must contain VERSION and exactly one CHANGELOG placeholder", file=sys.stderr)
    raise SystemExit(1)

rendered = template.replace("{{VERSION}}", version).replace("{{CHANGELOG}}", changelog)
if re.search(r"{{[^{}]+}}", rendered):
    print("Rendered release notes contain an unresolved placeholder", file=sys.stderr)
    raise SystemExit(1)
if not rendered.endswith("\n"):
    rendered += "\n"
try:
    with output_path.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(rendered)
except OSError as error:
    print(f"Unable to write release notes: {error}", file=sys.stderr)
    raise SystemExit(1)
PY
}

resolve_expected_metadata() {
  local expected_tag=${1:-}
  if [[ "${TEST_MODE}" == true ]]; then
    case "${VELOAUTH_RELEASE_TEST_CHANNEL:-local}" in
      local)
        [[ -z "${expected_tag}" ]] || fail "Local fixture candidate does not accept a release tag"
        EXPECTED_CHANNEL=local
        EXPECTED_COMMIT="${VELOAUTH_RELEASE_TEST_COMMIT:-0000000000000000000000000000000000000000}"
        EXPECTED_RUN_ID=local
        EXPECTED_MANIFEST_WORKFLOW=local
        [[ "${EXPECTED_COMMIT}" =~ ^[0-9a-f]{40}$ ]] \
          || fail "Test manifest commit must be 40 lowercase hexadecimal characters"
        return
        ;;
      tag) ;;
      *) fail "VELOAUTH_RELEASE_TEST_CHANNEL must be local or tag" ;;
    esac
  fi
  [[ "${TEST_MODE}" == false || "${TEST_MODE}" == true ]] \
    || fail "VELOAUTH_RELEASE_ARTIFACT_TEST_MODE must be true or false"
  [[ "${expected_tag}" == "${TAG}" ]] \
    || fail "Release candidate tag mismatch: expected ${TAG}, found ${expected_tag:-<empty>}"
  EXPECTED_COMMIT="$(git -C "${PROJECT_DIR}" rev-parse --verify HEAD^{commit} 2>/dev/null)" \
    || fail "Unable to resolve local source commit for release verification"
  EXPECTED_CHANNEL=tag
  EXPECTED_RUN_ID=__DECIMAL__
  EXPECTED_MANIFEST_WORKFLOW="${EXPECTED_WORKFLOW}"
  if [[ "${GITHUB_ACTIONS:-false}" == true ]]; then
    [[ "${GITHUB_REPOSITORY:-}" == "${REPOSITORY}" ]] \
      || fail "CI release verification requires GITHUB_REPOSITORY=${REPOSITORY}"
    [[ "${GITHUB_REF:-}" == "${EXPECTED_REF}" ]] \
      || fail "CI release verification requires GITHUB_REF=${EXPECTED_REF}"
    [[ "${GITHUB_WORKFLOW_REF:-}" == "${EXPECTED_WORKFLOW}" ]] \
      || fail "CI release verification requires GITHUB_WORKFLOW_REF=${EXPECTED_WORKFLOW}"
    [[ "${GITHUB_RUN_ID:-}" =~ ^[0-9]+$ ]] \
      || fail "CI release verification requires a decimal GITHUB_RUN_ID"
    [[ "${GITHUB_SHA:-}" == "${EXPECTED_COMMIT}" ]] \
      || fail "CI GITHUB_SHA does not match local source commit ${EXPECTED_COMMIT}"
    EXPECTED_RUN_ID="${GITHUB_RUN_ID}"
  fi
}

run_existing_candidate() {
  local candidate_dir=$1
  local expected_tag=${2:-}
  verify_candidate "${candidate_dir}" "${expected_tag}"
  local candidate_artifact="${candidate_dir}/${ARTIFACT_NAME}"
  if [[ "${TEST_MODE}" == true ]]; then
    local test_identity="${VELOAUTH_RELEASE_TEST_IDENTITY:-}"
    [[ "${test_identity}" == /* && -x "${test_identity}" ]] \
      || fail "Test --existing requires an absolute executable VELOAUTH_RELEASE_TEST_IDENTITY"
    "${test_identity}" "${TAG}" "${candidate_artifact}"
  else
    reject_build_environment_overrides
    initialize_work_dir
    local java_home
    java_home="$(discover_pinned_java_home)"
    configure_controlled_environment "${java_home}"
    "${SCRIPT_DIR}/verify-release-identity.sh" "${TAG}" "${candidate_artifact}"
  fi
  verify_candidate "${candidate_dir}" "${expected_tag}"
}

verify_candidate() {
  local candidate_dir=$1
  local expected_tag=${2:-}
  [[ "${candidate_dir}" == /* ]] || fail "Candidate directory path must be absolute: ${candidate_dir}"
  [[ -d "${candidate_dir}" && ! -L "${candidate_dir}" ]] \
    || fail "Candidate directory must be a real directory: ${candidate_dir}"

  local entries=()
  while IFS= read -r entry; do
    entries+=("${entry}")
  done < <(find "${candidate_dir}" -mindepth 1 -maxdepth 1 -print | LC_ALL=C sort)
  [[ ${#entries[@]} -eq 3 ]] \
    || fail "Release candidate must contain exactly three flat entries, found ${#entries[@]}"

  local artifact="${candidate_dir}/${ARTIFACT_NAME}"
  local checksum_file="${artifact}.sha256"
  local manifest_file="${artifact}.manifest.json"
  for required in "${artifact}" "${checksum_file}" "${manifest_file}"; do
    [[ -f "${required}" && ! -L "${required}" ]] \
      || fail "Missing regular non-symlink release candidate file: $(basename -- "${required}")"
  done

  local actual_sha expected_checksum_record
  actual_sha="$(sha256_file "${artifact}")"
  expected_checksum_record="${actual_sha}  ${ARTIFACT_NAME}"
  [[ "$(cat -- "${checksum_file}")" == "${expected_checksum_record}" ]] \
    || fail "Release checksum sidecar is non-canonical or does not match ${ARTIFACT_NAME}"
  [[ "$(wc -l <"${checksum_file}" | tr -d '[:space:]')" == 1 ]] \
    || fail "Release checksum sidecar must contain exactly one line"

  resolve_expected_metadata "${expected_tag}"
  python3 - "${manifest_file}" "${ARTIFACT_NAME}" "${BUILD_COMMAND}" \
    "${EXPECTED_CHANNEL}" "${EXPECTED_COMMIT}" "${JDK_IDENTITY}" "${MAVEN_IDENTITY}" \
    "${OUTPUT_TIMESTAMP}" "${REPOSITORY}" "${EXPECTED_RUN_ID}" "${actual_sha}" \
    "${VERSION}" "${EXPECTED_MANIFEST_WORKFLOW}" <<'PY'
import json
import pathlib
import re
import sys

(
    manifest_path,
    artifact,
    build_command,
    channel,
    commit,
    jdk,
    maven,
    output_timestamp,
    repository,
    run_id,
    sha256,
    version,
    workflow,
) = sys.argv[1:]

expected = {
    "artifact": artifact,
    "buildCommand": build_command,
    "channel": channel,
    "commit": commit,
    "jdk": jdk,
    "maven": maven,
    "outputTimestamp": output_timestamp,
    "repository": repository,
    "runId": run_id,
    "schemaVersion": 1,
    "sha256": sha256,
    "version": version,
    "workflow": workflow,
}

path = pathlib.Path(manifest_path)
try:
    raw = path.read_bytes()
    text = raw.decode("utf-8")
    actual = json.loads(text)
except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
    print(f"Unreadable release manifest: {error}", file=sys.stderr)
    raise SystemExit(1)

if run_id == "__DECIMAL__":
    actual_run_id = actual.get("runId") if type(actual) is dict else None
    if type(actual_run_id) is not str or re.fullmatch(r"[0-9]+", actual_run_id) is None:
        print("Release manifest runId must be a decimal string", file=sys.stderr)
        raise SystemExit(1)
    expected["runId"] = actual_run_id

if type(actual) is not dict or actual != expected:
    print("Release manifest schema or values do not match the canonical candidate", file=sys.stderr)
    raise SystemExit(1)
canonical = (json.dumps(expected, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")
if raw != canonical:
    print("Release manifest JSON encoding is not canonical", file=sys.stderr)
    raise SystemExit(1)
PY

  local size
  size="$(wc -c <"${artifact}" | tr -d '[:space:]')"
  echo "Verified single release candidate: ${ARTIFACT_NAME}; SHA-256 ${actual_sha}; size ${size} bytes"
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
      MVNW_REPOURL \
      VELOAUTH_PLUGIN_JAR \
      VELOAUTH_CTD_REQUIRE_PINNED_JAVA25 \
      VELOAUTH_SMOKE_COPY_DESTINATION \
      VELOAUTH_SMOKE_COPY_TEST_MODE \
      VELOAUTH_SMOKE_JAVA \
      VELOAUTH_SMOKE_MAVEN_REPOSITORY \
      VELOAUTH_SMOKE_MAVEN_SETTINGS \
      VELOAUTH_TEST_FORWARDING_MODE \
      VELOAUTH_TEST_RUNTIME_UPDATE \
      VELOAUTH_VELOCITY_LABEL \
      VELOAUTH_VELOCITY_SHA256 \
      VELOAUTH_VELOCITY_URL; do
    variable_value="${!variable_name-}"
    [[ -z "${variable_value}" ]] \
      || fail "Build-affecting environment variable must be empty or unset: ${variable_name}"
  done
}

initialize_work_dir() {
  TEMP_PARENT="$(cd -- "${TMPDIR:-/tmp}" && pwd -P)" \
    || fail "Unable to resolve the temporary directory"
  TEMP_PREFIX="${TEMP_PARENT%/}/veloauth-release-candidate."
  WORK_DIR="$(mktemp -d "${TEMP_PREFIX}XXXXXX")" \
    || fail "Unable to create release-candidate temporary directory"
  chmod 700 "${WORK_DIR}"
  TASK_MAVEN_USER_HOME="${WORK_DIR}/maven-user-home"
  TASK_MAVEN_SETTINGS="${WORK_DIR}/maven-settings.xml"
  TASK_MAVEN_REPOSITORY="${WORK_DIR}/maven-repository"
  mkdir -p "${TASK_MAVEN_USER_HOME}" "${TASK_MAVEN_REPOSITORY}"
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

configure_controlled_environment() {
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
  export VELOAUTH_SMOKE_MAVEN_SETTINGS="${TASK_MAVEN_SETTINGS}"
  export VELOAUTH_SMOKE_MAVEN_REPOSITORY="${TASK_MAVEN_REPOSITORY}"
  export VELOAUTH_RELEASE_MAVEN_SETTINGS="${TASK_MAVEN_SETTINGS}"
  export VELOAUTH_RELEASE_MAVEN_REPOSITORY="${TASK_MAVEN_REPOSITORY}"
  export TZ=UTC
  export LC_ALL=C
  export LANG=C
}

java_home_is_pinned() {
  local candidate=$1
  local metadata java_version java_runtime java_vendor java_vendor_version
  [[ -d "${candidate}" && -x "${candidate}/bin/java" ]] || return 1
  metadata="$("${candidate}/bin/java" -XshowSettings:properties -version 2>&1)" || return 1
  java_version="$(printf '%s\n' "${metadata}" | sed -n 's/^[[:space:]]*java\.version = //p' | head -n 1)"
  java_runtime="$(printf '%s\n' "${metadata}" | sed -n 's/^[[:space:]]*java\.runtime\.version = //p' | head -n 1)"
  java_vendor="$(printf '%s\n' "${metadata}" | sed -n 's/^[[:space:]]*java\.vendor = //p' | head -n 1)"
  java_vendor_version="$(printf '%s\n' "${metadata}" | sed -n 's/^[[:space:]]*java\.vendor\.version = //p' | head -n 1)"
  [[ "${java_version}" == "${PINNED_JAVA_VERSION}" \
      && ( "${java_runtime}" == "${PINNED_JAVA_RUNTIME_PREFIX}" \
        || "${java_runtime}" == "${PINNED_JAVA_RUNTIME_PREFIX}-LTS" ) \
      && "${java_vendor}" == "${PINNED_JAVA_VENDOR}" \
      && "${java_vendor_version}" == "${PINNED_JAVA_VENDOR_VERSION}" ]]
}

discover_pinned_java_home() {
  local candidates=()
  local candidate metadata path_java_home mac_java_home
  if [[ -n "${VELOAUTH_JAVA21_HOME:-}" ]]; then
    java_home_is_pinned "${VELOAUTH_JAVA21_HOME}" \
      || fail "VELOAUTH_JAVA21_HOME is not exact Temurin ${PINNED_JAVA_VERSION}+8"
    cd -- "${VELOAUTH_JAVA21_HOME}" && pwd -P
    return
  fi
  if [[ -x /usr/libexec/java_home ]]; then
    mac_java_home="$(/usr/libexec/java_home -v 21 2>/dev/null || true)"
    [[ -z "${mac_java_home}" ]] || candidates+=("${mac_java_home}")
  fi
  [[ -z "${JAVA_HOME:-}" ]] || candidates+=("${JAVA_HOME}")
  if command -v java >/dev/null 2>&1; then
    metadata="$(java -XshowSettings:properties -version 2>&1 || true)"
    path_java_home="$(printf '%s\n' "${metadata}" | sed -n 's/^[[:space:]]*java\.home = //p' | head -n 1)"
    [[ -z "${path_java_home}" ]] || candidates+=("${path_java_home}")
  fi
  for candidate in "${candidates[@]}"; do
    if java_home_is_pinned "${candidate}"; then
      cd -- "${candidate}" && pwd -P
      return
    fi
  done
  fail "Exact Temurin ${PINNED_JAVA_VERSION}+8 was not found; set VELOAUTH_JAVA21_HOME"
}

select_built_artifact() {
  local build_dir=$1
  local candidates=()
  if [[ -d "${build_dir}/target" ]]; then
    while IFS= read -r candidate; do
      candidates+=("${candidate}")
    done < <(find "${build_dir}/target" -maxdepth 1 -type f \
      -name 'veloauth-*.jar' ! -name 'original-*' -print | LC_ALL=C sort)
  fi
  [[ ${#candidates[@]} -eq 1 ]] \
    || fail "Canonical build must produce exactly one non-original target/veloauth-*.jar, found ${#candidates[@]}"
  [[ "$(basename -- "${candidates[0]}")" == "${ARTIFACT_NAME}" ]] \
    || fail "Canonical build artifact must be named ${ARTIFACT_NAME}"
  printf '%s\n' "${candidates[0]}"
}

prepare_empty_candidate_dir() {
  local candidate_dir=$1
  [[ "${candidate_dir}" == /* ]] || fail "Candidate directory path must be absolute: ${candidate_dir}"
  [[ -d "${candidate_dir}" && ! -L "${candidate_dir}" ]] \
    || fail "Candidate directory must be a real directory: ${candidate_dir}"
  [[ -z "$(find "${candidate_dir}" -mindepth 1 -maxdepth 1 -print -quit)" ]] \
    || fail "Candidate directory must be empty before canonical build: ${candidate_dir}"
}

copy_and_smoke_candidate() {
  local built_artifact=$1
  local candidate_dir=$2
  local reproducibility_verifier=$3
  local smoke_one=$4
  local smoke_two=$5
  local identity_verifier=$6
  local test_log=${7:-}
  local candidate_artifact="${candidate_dir}/${ARTIFACT_NAME}"
  cp -- "${built_artifact}" "${candidate_artifact}"
  local original_sha current_sha
  original_sha="$(sha256_file "${candidate_artifact}")"

  if [[ -n "${test_log}" ]]; then
    export VELOAUTH_RELEASE_TEST_INVOCATION_LOG="${test_log}"
  fi
  "${reproducibility_verifier}" --compare-existing "${candidate_artifact}"
  current_sha="$(sha256_file "${candidate_artifact}")"
  [[ "${current_sha}" == "${original_sha}" ]] \
    || fail "Release candidate changed during reproducibility verification"

  export VELOAUTH_PLUGIN_JAR="${candidate_artifact}"
  "${smoke_one}"
  current_sha="$(sha256_file "${candidate_artifact}")"
  [[ "${current_sha}" == "${original_sha}" ]] \
    || fail "Release candidate changed during the first smoke test"

  if [[ "${TEST_MODE}" == false ]]; then
    export VELOAUTH_CTD_REQUIRE_PINNED_JAVA25=true
  fi
  "${smoke_two}"
  current_sha="$(sha256_file "${candidate_artifact}")"
  [[ "${current_sha}" == "${original_sha}" ]] \
    || fail "Release candidate changed during the second smoke test"

  "${MANIFEST_CREATOR}" "${candidate_artifact}"
  if [[ "${TEST_MODE}" == true ]]; then
    verify_candidate "${candidate_dir}"
  else
    verify_candidate "${candidate_dir}" "${TAG}"
  fi
  "${identity_verifier}" "${TAG}" "${candidate_artifact}"
  current_sha="$(sha256_file "${candidate_artifact}")"
  [[ "${current_sha}" == "${original_sha}" ]] \
    || fail "Release candidate changed during release identity verification"
  if [[ "${TEST_MODE}" == true ]]; then
    verify_candidate "${candidate_dir}"
  else
    verify_candidate "${candidate_dir}" "${TAG}"
  fi
}

run_production_build() {
  local candidate_dir=$1
  [[ "$(git -C "${PROJECT_DIR}" rev-parse --is-inside-work-tree 2>/dev/null)" == true ]] \
    || fail "Canonical release build requires a Git worktree"
  [[ -z "$(git -C "${PROJECT_DIR}" status --porcelain=v1 --untracked-files=normal)" ]] \
    || fail "Canonical release build requires a clean Git HEAD"
  resolve_expected_metadata "${TAG}"
  [[ "$(git -C "${PROJECT_DIR}" rev-parse --verify HEAD^{commit})" == "${EXPECTED_COMMIT}" ]] \
    || fail "Canonical release build source does not match GITHUB_SHA"
  prepare_empty_candidate_dir "${candidate_dir}"
  reject_build_environment_overrides
  initialize_work_dir
  local java_home
  java_home="$(discover_pinned_java_home)"
  configure_controlled_environment "${java_home}"
  [[ -x "${PROJECT_DIR}/mvnw" ]] || fail "Checked-in ./mvnw is missing or not executable"
  local maven_version
  maven_version="$(cd -- "${PROJECT_DIR}" && ./mvnw -B -V -s "${TASK_MAVEN_SETTINGS}" \
    -Dmaven.repo.local="${TASK_MAVEN_REPOSITORY}" --version)"
  printf '%s\n' "${maven_version}"
  grep -Fq "Apache Maven ${PINNED_MAVEN_VERSION}" <<<"${maven_version}" \
    || fail "Canonical release build requires Apache Maven ${PINNED_MAVEN_VERSION}"
  grep -Fq "Java version: ${PINNED_JAVA_VERSION}" <<<"${maven_version}" \
    || fail "Canonical release build requires Java ${PINNED_JAVA_VERSION}"

  (
    cd -- "${PROJECT_DIR}"
    ./mvnw -B -V -s "${TASK_MAVEN_SETTINGS}" \
      -Dmaven.repo.local="${TASK_MAVEN_REPOSITORY}" \
      clean verify pmd:cpd-check -DskipTests=false
  )
  local built_artifact
  built_artifact="$(select_built_artifact "${PROJECT_DIR}")"
  copy_and_smoke_candidate "${built_artifact}" "${candidate_dir}" \
    "${SCRIPT_DIR}/verify-reproducible-jar.sh" \
    "${SCRIPT_DIR}/test-velocity-embedded.sh" "${SCRIPT_DIR}/test-velocity-ctd-embedded.sh" \
    "${SCRIPT_DIR}/verify-release-identity.sh"
}

run_test_build() {
  [[ $# -eq 8 ]] \
    || fail "Usage in test mode: $0 --test-build CANDIDATE_DIR BUILDER REPRO SMOKE_A SMOKE_B IDENTITY INVOCATION_LOG"
  local candidate_dir=$2
  local builder=$3
  local reproducibility_verifier=$4
  local smoke_one=$5
  local smoke_two=$6
  local identity_verifier=$7
  local invocation_log=$8
  for executable in "${builder}" "${reproducibility_verifier}" "${smoke_one}" \
      "${smoke_two}" "${identity_verifier}"; do
    [[ "${executable}" == /* && -x "${executable}" ]] \
      || fail "Test helper must be an absolute executable path: ${executable}"
  done
  [[ "${invocation_log}" == /* ]] || fail "Test invocation log path must be absolute"
  prepare_empty_candidate_dir "${candidate_dir}"
  reject_build_environment_overrides
  initialize_work_dir
  configure_controlled_environment
  local build_dir="${WORK_DIR}/test-build"
  mkdir -p "${build_dir}"
  "${builder}" "${build_dir}" "${invocation_log}"
  local built_artifact
  built_artifact="$(select_built_artifact "${build_dir}")"
  copy_and_smoke_candidate "${built_artifact}" "${candidate_dir}" \
    "${reproducibility_verifier}" "${smoke_one}" "${smoke_two}" \
    "${identity_verifier}" "${invocation_log}"
}

require_command awk
require_command basename
require_command cat
require_command chmod
require_command cp
require_command find
require_command git
require_command grep
require_command head
require_command mktemp
require_command mkdir
require_command mv
require_command python3
require_command rm
require_command sed
require_command sort
require_command tr
require_command wc
load_project_metadata
[[ -x "${MANIFEST_CREATOR}" ]] || fail "Missing executable manifest creator: ${MANIFEST_CREATOR}"
if [[ "${TEST_MODE}" != true ]]; then
  for test_variable in VELOAUTH_RELEASE_TEST_COMMIT VELOAUTH_RELEASE_TEST_CHANNEL \
      VELOAUTH_RELEASE_TEST_IDENTITY VELOAUTH_RELEASE_TEST_INVOCATION_LOG \
      VELOAUTH_RELEASE_TEST_VERSION VELOAUTH_RELEASE_TEST_OUTPUT_TIMESTAMP \
      VELOAUTH_RELEASE_TEST_EXISTING_IDENTITY_LOG; do
    [[ -z "${!test_variable-}" ]] \
      || fail "Test-only release override requires VELOAUTH_RELEASE_ARTIFACT_TEST_MODE=true: ${test_variable}"
  done
fi

if [[ ${1:-} == --render-notes ]]; then
  shift
  render_release_notes "$@"
  exit 0
fi

case "${1:-}" in
  --existing)
    if [[ "${TEST_MODE}" == true ]]; then
      case "${VELOAUTH_RELEASE_TEST_CHANNEL:-local}" in
        local) [[ $# -eq 2 ]] \
          || fail "Usage in local test mode: $0 --existing /absolute/candidate/directory" ;;
        tag) [[ $# -eq 3 ]] \
          || fail "Usage in tag test mode: $0 --existing /absolute/candidate/directory ${TAG}" ;;
        *) fail "VELOAUTH_RELEASE_TEST_CHANNEL must be local or tag" ;;
      esac
    else
      [[ $# -eq 3 ]] || fail "Usage: $0 --existing /absolute/candidate/directory ${TAG}"
    fi
    run_existing_candidate "$2" "${3:-}"
    ;;
  --build)
    [[ $# -eq 2 ]] || fail "Usage: $0 --build /absolute/empty/candidate/directory"
    [[ "${TEST_MODE}" == false ]] \
      || fail "Production --build is unavailable in release-artifact test mode"
    run_production_build "$2"
    ;;
  --test-build)
    [[ "${TEST_MODE}" == true ]] \
      || fail "Test-only release build hook requires VELOAUTH_RELEASE_ARTIFACT_TEST_MODE=true"
    run_test_build "$@"
    ;;
  *)
    fail "Usage: $0 --build DIR | --existing DIR TAG | --render-notes TEMPLATE CHANGELOG OUTPUT VERSION"
    ;;
esac
