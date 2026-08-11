#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
VERIFIER="${SCRIPT_DIR}/verify-reproducible-jar.sh"
TEMP_PARENT="$(cd -- "${TMPDIR:-/tmp}" && pwd -P)"
TEMP_PREFIX="${TEMP_PARENT%/}/veloauth-reproducible-test."
TEMP_DIR=""

fail() {
  echo "TEST FAILURE: $1" >&2
  exit 1
}

cleanup() {
  local exit_status=$?
  trap - EXIT
  if [[ -n "${TEMP_DIR}" && "${TEMP_DIR}" == "${TEMP_PREFIX}"?????? \
      && -d "${TEMP_DIR}" && ! -L "${TEMP_DIR}" && -O "${TEMP_DIR}" ]]; then
    rm -rf -- "${TEMP_DIR}"
  fi
  exit "${exit_status}"
}

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

run_expect_failure() {
  local output_file=$1
  shift
  if "$@" >"${output_file}" 2>&1; then
    fail "command unexpectedly succeeded: $*"
  fi
}

trap cleanup EXIT
TEMP_DIR="$(mktemp -d "${TEMP_PREFIX}XXXXXX")"
chmod 700 "${TEMP_DIR}"

[[ -x "${VERIFIER}" ]] || fail "missing executable verifier: ${VERIFIER}"
if grep -Eq '(^|[[:space:]])eval([[:space:]]|$)' "${VERIFIER}"; then
  fail "verifier must not execute shell text with eval"
fi

FAKE_BUILDER="${TEMP_DIR}/fake-builder.sh"
printf '%s\n' \
  '#!/usr/bin/env bash' \
  'set -euo pipefail' \
  'BUILD_DIR=$1' \
  'INVOCATION_LOG=$2' \
  '[[ -d "${BUILD_DIR}" ]]' \
  '[[ -z "$(find "${BUILD_DIR}" -mindepth 1 -print -quit)" ]]' \
  '[[ "${MAVEN_SKIP_RC:-}" == true ]]' \
  '[[ "${MAVEN_USER_HOME:-}" == */maven-user-home ]]' \
  '[[ -f "${VELOAUTH_REPRO_MAVEN_SETTINGS:-}" ]]' \
  'grep -Fq "<settings" "${VELOAUTH_REPRO_MAVEN_SETTINGS}"' \
  'printf "%s\\n" "${BUILD_DIR}" >>"${INVOCATION_LOG}"' \
  'mkdir -p "${BUILD_DIR}/target"' \
  'printf "orchestrated artifact\\n" >"${BUILD_DIR}/target/veloauth-1.5.0.jar"' \
  >"${FAKE_BUILDER}"
chmod 700 "${FAKE_BUILDER}"
INVOCATION_LOG="${TEMP_DIR}/fake-builder.invocations"
ORCHESTRATION_OUTPUT="${TEMP_DIR}/orchestration.out"
VELOAUTH_REPRO_TEST_MODE=true "${VERIFIER}" --test-orchestrate \
  "${FAKE_BUILDER}" "${INVOCATION_LOG}" >"${ORCHESTRATION_OUTPUT}" 2>&1 \
  || fail "verifier must orchestrate two deterministic fake builds"
[[ "$(awk 'END { print NR + 0 }' "${INVOCATION_LOG}")" == 2 ]] \
  || fail "fake builder must be invoked exactly twice"
FIRST_BUILD_DIR="$(sed -n '1p' "${INVOCATION_LOG}")"
SECOND_BUILD_DIR="$(sed -n '2p' "${INVOCATION_LOG}")"
[[ -n "${FIRST_BUILD_DIR}" && -n "${SECOND_BUILD_DIR}" \
    && "${FIRST_BUILD_DIR}" != "${SECOND_BUILD_DIR}" ]] \
  || fail "fake builds must receive two distinct directories"
[[ "${FIRST_BUILD_DIR}" == */veloauth-reproducible.??????/test-build-a \
    && "${SECOND_BUILD_DIR}" == */veloauth-reproducible.??????/test-build-b ]] \
  || fail "fake builds must run inside verifier-owned directories"
[[ ! -e "${FIRST_BUILD_DIR}" && ! -e "${SECOND_BUILD_DIR}" ]] \
  || fail "orchestrated build directories must be cleaned after verification"
grep -Fq "Reproducible artifact verified" "${ORCHESTRATION_OUTPUT}" \
  || fail "orchestrated verifier success output is missing"

FIXTURE_A="${TEMP_DIR}/fixture-a"
FIXTURE_B="${TEMP_DIR}/fixture-b"
mkdir -p "${FIXTURE_A}/target" "${FIXTURE_B}/target"
printf 'same artifact\n' >"${FIXTURE_A}/target/veloauth-1.5.0.jar"
cp "${FIXTURE_A}/target/veloauth-1.5.0.jar" "${FIXTURE_B}/target/veloauth-1.5.0.jar"

EQUAL_OUTPUT="${TEMP_DIR}/equal.out"
VELOAUTH_REPRO_TEST_MODE=true "${VERIFIER}" --test-compare \
  "${FIXTURE_A}" "${FIXTURE_B}" >"${EQUAL_OUTPUT}" 2>&1 \
  || fail "equal artifacts must pass"
grep -Fq "Reproducible artifact verified" "${EQUAL_OUTPUT}" \
  || fail "equal-artifact success output is missing"

printf 'same artifacu\n' >"${FIXTURE_B}/target/veloauth-1.5.0.jar"
SHA_A="$(sha256_file "${FIXTURE_A}/target/veloauth-1.5.0.jar")"
SHA_B="$(sha256_file "${FIXTURE_B}/target/veloauth-1.5.0.jar")"
[[ "${SHA_A}" != "${SHA_B}" ]] || fail "difference fixture must have distinct hashes"
DIFFERENT_OUTPUT="${TEMP_DIR}/different.out"
run_expect_failure "${DIFFERENT_OUTPUT}" env VELOAUTH_REPRO_TEST_MODE=true \
  "${VERIFIER}" --test-compare "${FIXTURE_A}" "${FIXTURE_B}"
grep -Fq "Build A SHA-256: ${SHA_A}" "${DIFFERENT_OUTPUT}" \
  || fail "mismatch output must contain independently calculated build A hash"
grep -Fq "Build B SHA-256: ${SHA_B}" "${DIFFERENT_OUTPUT}" \
  || fail "mismatch output must contain independently calculated build B hash"

rm -- "${FIXTURE_A}/target/veloauth-1.5.0.jar"
MISSING_OUTPUT="${TEMP_DIR}/missing.out"
run_expect_failure "${MISSING_OUTPUT}" env VELOAUTH_REPRO_TEST_MODE=true \
  "${VERIFIER}" --test-compare "${FIXTURE_A}" "${FIXTURE_B}"
grep -Fq "Build A: expected exactly one non-original target/veloauth-*.jar, found 0" \
  "${MISSING_OUTPUT}" || fail "missing candidate must fail specifically"

printf 'first\n' >"${FIXTURE_A}/target/veloauth-1.5.0.jar"
printf 'second\n' >"${FIXTURE_A}/target/veloauth-1.5.1.jar"
AMBIGUOUS_OUTPUT="${TEMP_DIR}/ambiguous.out"
run_expect_failure "${AMBIGUOUS_OUTPUT}" env VELOAUTH_REPRO_TEST_MODE=true \
  "${VERIFIER}" --test-compare "${FIXTURE_A}" "${FIXTURE_B}"
grep -Fq "Build A: expected exactly one non-original target/veloauth-*.jar, found 2" \
  "${AMBIGUOUS_OUTPUT}" || fail "ambiguous candidate must fail specifically"

HOOK_OUTPUT="${TEMP_DIR}/hook.out"
run_expect_failure "${HOOK_OUTPUT}" "${VERIFIER}" --test-compare "${FIXTURE_A}" "${FIXTURE_B}"
grep -Fq "Test-only verifier hooks require VELOAUTH_REPRO_TEST_MODE=true" "${HOOK_OUTPUT}" \
  || fail "test hook must be inaccessible without explicit test mode"

BUILD_AFFECTING_ENVIRONMENT=(
  MAVEN_ARGS
  MAVEN_OPTS
  MAVEN_DEBUG_OPTS
  JAVA_TOOL_OPTIONS
  JDK_JAVA_OPTIONS
  _JAVA_OPTIONS
  JDK_JAVAC_OPTIONS
  SOURCE_DATE_EPOCH
  MAVEN_BASEDIR
  MAVEN_CONFIG
  MAVEN_PROJECTBASEDIR
  MVNW_REPOURL
)
CLEAN_BUILD_ENVIRONMENT=(env)
for variable_name in "${BUILD_AFFECTING_ENVIRONMENT[@]}"; do
  CLEAN_BUILD_ENVIRONMENT+=(-u "${variable_name}")
done
for variable_name in "${BUILD_AFFECTING_ENVIRONMENT[@]}"; do
  ENVIRONMENT_OUTPUT="${TEMP_DIR}/environment-${variable_name}.out"
  run_expect_failure "${ENVIRONMENT_OUTPUT}" "${CLEAN_BUILD_ENVIRONMENT[@]}" \
    VELOAUTH_JAVA21_HOME="${TEMP_DIR}/missing-jdk" \
    "${variable_name}=fixture-override" "${VERIFIER}"
  grep -Fq "Build-affecting environment variable must be empty or unset: ${variable_name}" \
    "${ENVIRONMENT_OUTPUT}" \
    || fail "${variable_name} must fail before JDK discovery or either Maven build"
done
EMPTY_ENVIRONMENT_OUTPUT="${TEMP_DIR}/environment-empty.out"
run_expect_failure "${EMPTY_ENVIRONMENT_OUTPUT}" "${CLEAN_BUILD_ENVIRONMENT[@]}" \
  VELOAUTH_JAVA21_HOME="${TEMP_DIR}/missing-jdk" MAVEN_ARGS= "${VERIFIER}"
if grep -Fq "Build-affecting environment variable must be empty or unset" \
    "${EMPTY_ENVIRONMENT_OUTPUT}"; then
  fail "an explicitly empty build-affecting variable must remain allowed"
fi

CLEANUP_PARENT="${TEMP_DIR}/cleanup-parent"
mkdir -p "${CLEANUP_PARENT}/unrelated-sibling"
printf 'keep\n' >"${CLEANUP_PARENT}/unrelated-sibling/marker"
CLEANUP_OUTPUT="${TEMP_DIR}/cleanup.out"
run_expect_failure "${CLEANUP_OUTPUT}" env TMPDIR="${CLEANUP_PARENT}" \
  VELOAUTH_REPRO_TEST_MODE=true "${VERIFIER}" --test-cleanup-probe
[[ -f "${CLEANUP_PARENT}/unrelated-sibling/marker" ]] \
  || fail "verifier cleanup removed an unrelated sibling"
if find "${CLEANUP_PARENT}" -mindepth 1 -maxdepth 1 -type d \
    -name 'veloauth-reproducible.*' -print -quit | grep -q .; then
  fail "verifier-owned temporary directory survived failure cleanup"
fi

echo "Reproducible JAR verifier fixture tests passed"
