#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd -P)"
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

fail() {
  echo "$1" >&2
  exit 1
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

evaluate_maven_expression() {
  local expression=$1
  local output
  output="$(
    cd -- "${PROJECT_DIR}"
    ./mvnw -B -ntp -s "${VELOAUTH_RELEASE_MAVEN_SETTINGS}" \
      -Dmaven.repo.local="${VELOAUTH_RELEASE_MAVEN_REPOSITORY}" \
      help:evaluate -Dstyle.color=never -DforceStdout -Dexpression="${expression}"
  )" || fail "Unable to evaluate Maven expression: ${expression}"
  printf '%s\n' "${output}" | awk 'NF && $0 !~ /^\[/ { value=$0 } END { print value }'
}

validate_pinned_java() {
  local metadata java_version java_runtime java_vendor java_vendor_version
  [[ -n "${JAVA_HOME:-}" && -x "${JAVA_HOME}/bin/java" ]] \
    || fail "Canonical manifest creation requires an explicit JAVA_HOME"
  metadata="$("${JAVA_HOME}/bin/java" -XshowSettings:properties -version 2>&1)" \
    || fail "Unable to inspect canonical Java runtime"
  java_version="$(printf '%s\n' "${metadata}" | sed -n 's/^[[:space:]]*java\.version = //p' | head -n 1)"
  java_runtime="$(printf '%s\n' "${metadata}" | sed -n 's/^[[:space:]]*java\.runtime\.version = //p' | head -n 1)"
  java_vendor="$(printf '%s\n' "${metadata}" | sed -n 's/^[[:space:]]*java\.vendor = //p' | head -n 1)"
  java_vendor_version="$(printf '%s\n' "${metadata}" | sed -n 's/^[[:space:]]*java\.vendor\.version = //p' | head -n 1)"
  [[ "${java_version}" == "${PINNED_JAVA_VERSION}" \
      && ( "${java_runtime}" == "${PINNED_JAVA_RUNTIME_PREFIX}" \
        || "${java_runtime}" == "${PINNED_JAVA_RUNTIME_PREFIX}-LTS" ) \
      && "${java_vendor}" == "${PINNED_JAVA_VENDOR}" \
      && "${java_vendor_version}" == "${PINNED_JAVA_VENDOR_VERSION}" ]] \
    || fail "Canonical manifest creation requires exact Temurin ${PINNED_JAVA_VERSION}+8"
}

[[ $# -eq 1 ]] || fail "Usage: $0 /absolute/path/to/veloauth-VERSION.jar"
ARTIFACT=$1
[[ "${ARTIFACT}" == /* ]] || fail "Release artifact path must be absolute: ${ARTIFACT}"
[[ -f "${ARTIFACT}" && ! -L "${ARTIFACT}" ]] \
  || fail "Release artifact must be a regular non-symlink file: ${ARTIFACT}"

TEST_COMMIT="${VELOAUTH_RELEASE_TEST_COMMIT:-}"
for test_variable in VELOAUTH_RELEASE_TEST_COMMIT VELOAUTH_RELEASE_TEST_VERSION \
    VELOAUTH_RELEASE_TEST_OUTPUT_TIMESTAMP; do
  if [[ "${TEST_MODE}" != true && -n "${!test_variable-}" ]]; then
    fail "Test-only manifest override requires VELOAUTH_RELEASE_ARTIFACT_TEST_MODE=true: ${test_variable}"
  fi
done

case "${TEST_MODE}" in
  false)
    [[ -x "${PROJECT_DIR}/mvnw" ]] || fail "Checked-in ./mvnw is missing or not executable"
    [[ "${VELOAUTH_RELEASE_MAVEN_SETTINGS:-}" == /* \
        && -f "${VELOAUTH_RELEASE_MAVEN_SETTINGS}" \
        && ! -L "${VELOAUTH_RELEASE_MAVEN_SETTINGS}" ]] \
      || fail "Canonical manifest creation requires an absolute controlled Maven settings file"
    [[ "${VELOAUTH_RELEASE_MAVEN_REPOSITORY:-}" == /* \
        && -d "${VELOAUTH_RELEASE_MAVEN_REPOSITORY}" \
        && ! -L "${VELOAUTH_RELEASE_MAVEN_REPOSITORY}" ]] \
      || fail "Canonical manifest creation requires an absolute isolated Maven repository"
    [[ "${MAVEN_SKIP_RC:-}" == true ]] \
      || fail "Canonical manifest creation requires MAVEN_SKIP_RC=true"
    validate_pinned_java
    MAVEN_VERSION_OUTPUT="$(
      cd -- "${PROJECT_DIR}"
      ./mvnw -B -V -s "${VELOAUTH_RELEASE_MAVEN_SETTINGS}" \
        -Dmaven.repo.local="${VELOAUTH_RELEASE_MAVEN_REPOSITORY}" --version
    )" || fail "Unable to inspect the canonical Maven runtime"
    grep -Fq "Apache Maven ${PINNED_MAVEN_VERSION}" <<<"${MAVEN_VERSION_OUTPUT}" \
      || fail "Canonical manifest creation requires Apache Maven ${PINNED_MAVEN_VERSION}"
    grep -Fq "Java version: ${PINNED_JAVA_VERSION}" <<<"${MAVEN_VERSION_OUTPUT}" \
      || fail "Canonical manifest creation requires Java ${PINNED_JAVA_VERSION}"
    VERSION="$(evaluate_maven_expression project.version)"
    OUTPUT_TIMESTAMP="$(evaluate_maven_expression project.build.outputTimestamp)"
    [[ "${VERSION}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] \
      || fail "Maven project version is not a release version: ${VERSION:-<empty>}"
    [[ "${OUTPUT_TIMESTAMP}" == "2026-08-11T00:00:00Z" ]] \
      || fail "Unexpected project.build.outputTimestamp: ${OUTPUT_TIMESTAMP:-<empty>}"
    TAG="v${VERSION}"
    EXPECTED_REF="refs/tags/${TAG}"
    EXPECTED_WORKFLOW="${REPOSITORY}/.github/workflows/build-and-release.yml@${EXPECTED_REF}"
    [[ "${GITHUB_REPOSITORY:-}" == "${REPOSITORY}" ]] \
      || fail "Release manifest requires GITHUB_REPOSITORY=${REPOSITORY}"
    [[ "${GITHUB_REF:-}" == "${EXPECTED_REF}" ]] \
      || fail "Release manifest requires GITHUB_REF=${EXPECTED_REF}"
    [[ "${GITHUB_WORKFLOW_REF:-}" == "${EXPECTED_WORKFLOW}" ]] \
      || fail "Release manifest requires GITHUB_WORKFLOW_REF=${EXPECTED_WORKFLOW}"
    [[ "${GITHUB_RUN_ID:-}" =~ ^[0-9]+$ ]] \
      || fail "Release manifest requires a decimal GITHUB_RUN_ID"
    [[ "${GITHUB_SHA:-}" =~ ^[0-9a-f]{40}$ ]] \
      || fail "Release manifest requires a 40-character lowercase GITHUB_SHA"
    HEAD_COMMIT="$(git -C "${PROJECT_DIR}" rev-parse --verify HEAD^{commit} 2>/dev/null)" \
      || fail "Unable to resolve the release source commit"
    [[ -z "$(git -C "${PROJECT_DIR}" status --porcelain=v1 --untracked-files=normal)" ]] \
      || fail "Canonical manifest creation requires a clean Git HEAD"
    [[ "${HEAD_COMMIT}" == "${GITHUB_SHA}" ]] \
      || fail "Release source commit mismatch: Git HEAD ${HEAD_COMMIT}, GITHUB_SHA ${GITHUB_SHA}"
    CHANNEL=tag
    COMMIT="${GITHUB_SHA}"
    RUN_ID="${GITHUB_RUN_ID}"
    WORKFLOW="${GITHUB_WORKFLOW_REF}"
    ;;
  true)
    # Default to the POM version. The production branch above resolves it through Maven;
    # test mode reads it offline so a version bump cannot leave this default stale.
    if [[ -n "${VELOAUTH_RELEASE_TEST_VERSION:-}" ]]; then
      VERSION="${VELOAUTH_RELEASE_TEST_VERSION}"
    else
      VERSION="$("${SCRIPT_DIR}/print-project-version.sh")" \
        || fail "Unable to resolve the Maven project version for test-mode manifest creation"
      VERSION="${VERSION#version=}"
    fi
    OUTPUT_TIMESTAMP="${VELOAUTH_RELEASE_TEST_OUTPUT_TIMESTAMP:-2026-08-11T00:00:00Z}"
    [[ "${VERSION}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] \
      || fail "Test manifest version must be a release version"
    COMMIT="${TEST_COMMIT:-0000000000000000000000000000000000000000}"
    [[ "${COMMIT}" =~ ^[0-9a-f]{40}$ ]] \
      || fail "Test manifest commit must be 40 lowercase hexadecimal characters"
    CHANNEL=local
    RUN_ID=local
    WORKFLOW=local
    ;;
  *)
    fail "VELOAUTH_RELEASE_ARTIFACT_TEST_MODE must be true or false"
    ;;
esac

ARTIFACT_NAME="veloauth-${VERSION}.jar"
[[ "$(basename -- "${ARTIFACT}")" == "${ARTIFACT_NAME}" ]] \
  || fail "Release artifact must be named ${ARTIFACT_NAME}"

CHECKSUM="$(sha256_file "${ARTIFACT}")"
[[ "${CHECKSUM}" =~ ^[0-9a-f]{64}$ ]] || fail "Unable to calculate release artifact SHA-256"
CHECKSUM_FILE="${ARTIFACT}.sha256"
MANIFEST_FILE="${ARTIFACT}.manifest.json"
[[ ! -e "${CHECKSUM_FILE}" && ! -e "${MANIFEST_FILE}" ]] \
  || fail "Release checksum or manifest already exists; refusing to overwrite candidate metadata"
CHECKSUM_TEMP="$(mktemp "${CHECKSUM_FILE}.tmp.XXXXXX")" \
  || fail "Unable to create checksum temporary file"
MANIFEST_TEMP="$(mktemp "${MANIFEST_FILE}.tmp.XXXXXX")" \
  || {
    rm -f -- "${CHECKSUM_TEMP}"
    fail "Unable to create manifest temporary file"
  }

cleanup_temporary_files() {
  local exit_status=$?
  trap - EXIT
  rm -f -- "${CHECKSUM_TEMP}" "${MANIFEST_TEMP}"
  exit "${exit_status}"
}
trap cleanup_temporary_files EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

umask 077
printf '%s  %s\n' "${CHECKSUM}" "${ARTIFACT_NAME}" >"${CHECKSUM_TEMP}"
python3 - "${MANIFEST_TEMP}" \
  "${ARTIFACT_NAME}" "${BUILD_COMMAND}" "${CHANNEL}" "${COMMIT}" \
  "${JDK_IDENTITY}" "${MAVEN_IDENTITY}" "${OUTPUT_TIMESTAMP}" "${REPOSITORY}" \
  "${RUN_ID}" "${CHECKSUM}" "${VERSION}" "${WORKFLOW}" <<'PY'
import json
import sys

(
    output,
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

manifest = {
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

with open(output, "w", encoding="utf-8", newline="\n") as stream:
    json.dump(manifest, stream, ensure_ascii=False, indent=2, sort_keys=True)
    stream.write("\n")
PY

POST_WRITE_CHECKSUM="$(sha256_file "${ARTIFACT}")"
[[ "${POST_WRITE_CHECKSUM}" == "${CHECKSUM}" ]] \
  || fail "Release artifact changed while its metadata was being created"
chmod 0644 "${CHECKSUM_TEMP}" "${MANIFEST_TEMP}"
mv -- "${CHECKSUM_TEMP}" "${CHECKSUM_FILE}"
mv -- "${MANIFEST_TEMP}" "${MANIFEST_FILE}"
trap - EXIT HUP INT TERM

echo "Created release checksum and manifest for ${ARTIFACT_NAME}: ${CHECKSUM}"
