#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd -P)"
MANIFEST_CREATOR="${SCRIPT_DIR}/create-release-manifest.sh"
CANDIDATE_VERIFIER="${SCRIPT_DIR}/verify-release-candidate.sh"
EMBEDDED_SMOKE="${SCRIPT_DIR}/test-velocity-embedded.sh"
CTD_SMOKE="${SCRIPT_DIR}/test-velocity-ctd-embedded.sh"
WORKFLOW="${PROJECT_DIR}/.github/workflows/build-and-release.yml"
RELEASE_TEMPLATE="${PROJECT_DIR}/.github/RELEASE_TEMPLATE.md"
TEMP_PARENT="$(cd -- "${TMPDIR:-/tmp}" && pwd -P)"
TEMP_PREFIX="${TEMP_PARENT%/}/veloauth-release-artifacts-test."
TEMP_DIR=""

fail() {
  echo "TEST FAILURE: $1" >&2
  exit 1
}

# Fixtures are validated against the real project identity, so they must track the POM
# version instead of hardcoding one. FOREIGN_VERSION is the deliberately-wrong value used
# by mismatch fixtures; it can never collide with a released version.
VERSION="$("${SCRIPT_DIR}/print-project-version.sh")" \
  || fail "cannot resolve the Maven project version"
VERSION="${VERSION#version=}"
FOREIGN_VERSION="0.0.0"
JAR_NAME="veloauth-${VERSION}.jar"
TAG="v${VERSION}"

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
  local output=$1
  shift
  if "$@" >"${output}" 2>&1; then
    fail "command unexpectedly succeeded: $*"
  fi
}

assert_contains() {
  local file=$1
  local expected=$2
  local description=$3
  grep -Fq -- "${expected}" "${file}" || fail "${description}"
}

# Offline-verification fixtures must not inherit the runner's GitHub Actions metadata.
# They exist to prove a downloaded candidate verifies without live CI context, but the
# verifier switches to its CI branch whenever GITHUB_ACTIONS=true and then demands
# GITHUB_REF=refs/tags/<tag> — never true on a branch push, so these assertions could only
# ever pass outside CI. Scrubbing the ambient values makes the fixture mean the same thing
# on a workstation and on a runner.
without_ci_metadata() {
  env -u GITHUB_ACTIONS -u GITHUB_REPOSITORY -u GITHUB_REF -u GITHUB_WORKFLOW_REF \
    -u GITHUB_RUN_ID -u GITHUB_SHA "$@"
}

copy_candidate() {
  local source=$1
  local destination=$2
  mkdir -p "${destination}"
  cp -- "${source}/${JAR_NAME}" \
    "${source}/${JAR_NAME}.sha256" \
    "${source}/${JAR_NAME}.manifest.json" "${destination}/"
}

trap cleanup EXIT
TEMP_DIR="$(mktemp -d "${TEMP_PREFIX}XXXXXX")"
chmod 700 "${TEMP_DIR}"
EXISTING_IDENTITY="${TEMP_DIR}/existing-identity.sh"
cat >"${EXISTING_IDENTITY}" <<SH
#!/usr/bin/env bash
set -euo pipefail
[[ "\$1" == "${TAG}" ]]
[[ "\$2" == /*/${JAR_NAME} && -f "\$2" ]]
if [[ -n "\${VELOAUTH_RELEASE_TEST_EXISTING_IDENTITY_LOG:-}" ]]; then
  printf 'existing-identity:%s\n' "\$2" >>"\${VELOAUTH_RELEASE_TEST_EXISTING_IDENTITY_LOG}"
fi
if grep -Fq 'invalid-internal-identity' "\$2"; then
  echo "Fixture internal release identity mismatch" >&2
  exit 1
fi
SH
chmod 700 "${EXISTING_IDENTITY}"

for helper in "${MANIFEST_CREATOR}" "${CANDIDATE_VERIFIER}" "${EMBEDDED_SMOKE}" "${CTD_SMOKE}"; do
  [[ -x "${helper}" ]] || fail "expected executable helper: ${helper}"
  if grep -Eq '(^|[[:space:]])eval([[:space:]]|$)' "${helper}"; then
    fail "release helpers must not execute shell text with eval: ${helper}"
  fi
done

# The manifest is exact, canonical, deterministic, and binds all candidate metadata.
VALID_CANDIDATE="${TEMP_DIR}/valid-candidate"
mkdir -p "${VALID_CANDIDATE}"
printf 'deterministic release candidate\n' >"${VALID_CANDIDATE}/${JAR_NAME}"
TEST_COMMIT="0123456789abcdef0123456789abcdef01234567"
VELOAUTH_RELEASE_ARTIFACT_TEST_MODE=true \
VELOAUTH_RELEASE_TEST_COMMIT="${TEST_COMMIT}" \
  "${MANIFEST_CREATOR}" "${VALID_CANDIDATE}/${JAR_NAME}" \
  >"${TEMP_DIR}/manifest-create.out"
VALID_SHA="$(sha256_file "${VALID_CANDIDATE}/${JAR_NAME}")"
[[ "$(cat "${VALID_CANDIDATE}/${JAR_NAME}.sha256")" \
    == "${VALID_SHA}  ${JAR_NAME}" ]] \
  || fail "checksum sidecar must be canonical and bind the exact artifact name"
python3 - "${VALID_CANDIDATE}/${JAR_NAME}.manifest.json" \
  "${VALID_SHA}" "${TEST_COMMIT}" "${JAR_NAME}" "${VERSION}" <<'PY' || exit 1
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
sha256 = sys.argv[2]
commit = sys.argv[3]
expected = {
    "artifact": sys.argv[4],
    "buildCommand": "./mvnw -B -V clean verify pmd:cpd-check -DskipTests=false",
    "channel": "local",
    "commit": commit,
    "jdk": "Eclipse Temurin 21.0.12+8",
    "maven": "Apache Maven 3.9.16",
    "outputTimestamp": "2026-08-11T00:00:00Z",
    "repository": "rafalohaki/VeloAuth",
    "runId": "local",
    "schemaVersion": 1,
    "sha256": sha256,
    "version": sys.argv[5],
    "workflow": "local",
}
raw = path.read_bytes()
actual = json.loads(raw.decode("utf-8"))
if actual != expected or type(actual["schemaVersion"]) is not int:
    raise SystemExit("TEST FAILURE: manifest values or types are not exact")
if list(actual) != sorted(expected):
    raise SystemExit("TEST FAILURE: manifest keys are not lexicographically ordered")
canonical = (json.dumps(expected, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode()
if raw != canonical:
    raise SystemExit("TEST FAILURE: manifest bytes are not canonical")
PY

VERIFY_OUTPUT="${TEMP_DIR}/verify-valid.out"
VALID_IDENTITY_LOG="${TEMP_DIR}/verify-valid-identity.log"
VELOAUTH_RELEASE_ARTIFACT_TEST_MODE=true \
VELOAUTH_RELEASE_TEST_COMMIT="${TEST_COMMIT}" \
VELOAUTH_RELEASE_TEST_IDENTITY="${EXISTING_IDENTITY}" \
VELOAUTH_RELEASE_TEST_EXISTING_IDENTITY_LOG="${VALID_IDENTITY_LOG}" \
  "${CANDIDATE_VERIFIER}" --existing "${VALID_CANDIDATE}" \
  >"${VERIFY_OUTPUT}" 2>&1 || fail "valid three-file candidate must pass"
assert_contains "${VERIFY_OUTPUT}" "Verified single release candidate" \
  "valid-candidate success evidence is missing"
[[ "$(grep -c '^existing-identity:' "${VALID_IDENTITY_LOG}")" == 1 ]] \
  || fail "--existing must run Task5 internal identity exactly once"

INTERNAL_MISMATCH="${TEMP_DIR}/internal-mismatch"
mkdir -p "${INTERNAL_MISMATCH}"
printf 'invalid-internal-identity\n' >"${INTERNAL_MISMATCH}/${JAR_NAME}"
VELOAUTH_RELEASE_ARTIFACT_TEST_MODE=true VELOAUTH_RELEASE_TEST_COMMIT="${TEST_COMMIT}" \
  "${MANIFEST_CREATOR}" "${INTERNAL_MISMATCH}/${JAR_NAME}" >/dev/null
run_expect_failure "${TEMP_DIR}/internal-mismatch.out" env \
  VELOAUTH_RELEASE_ARTIFACT_TEST_MODE=true VELOAUTH_RELEASE_TEST_COMMIT="${TEST_COMMIT}" \
  VELOAUTH_RELEASE_TEST_IDENTITY="${EXISTING_IDENTITY}" \
  "${CANDIDATE_VERIFIER}" --existing "${INTERNAL_MISMATCH}"
assert_contains "${TEMP_DIR}/internal-mismatch.out" \
  "Fixture internal release identity mismatch" \
  "checksum-consistent JAR with invalid internal identity must fail --existing"

# Any missing, ambiguous, malformed, mutated, or non-canonical artifact set is rejected.
MISSING="${TEMP_DIR}/missing-candidate"
copy_candidate "${VALID_CANDIDATE}" "${MISSING}"
rm -- "${MISSING}/${JAR_NAME}.manifest.json"
run_expect_failure "${TEMP_DIR}/missing.out" env \
  VELOAUTH_RELEASE_ARTIFACT_TEST_MODE=true VELOAUTH_RELEASE_TEST_COMMIT="${TEST_COMMIT}" \
  "${CANDIDATE_VERIFIER}" --existing "${MISSING}"
assert_contains "${TEMP_DIR}/missing.out" "exactly three flat entries, found 2" \
  "missing candidate entry must fail specifically"

AMBIGUOUS="${TEMP_DIR}/ambiguous-candidate"
copy_candidate "${VALID_CANDIDATE}" "${AMBIGUOUS}"
printf 'extra\n' >"${AMBIGUOUS}/unexpected.txt"
run_expect_failure "${TEMP_DIR}/ambiguous.out" env \
  VELOAUTH_RELEASE_ARTIFACT_TEST_MODE=true VELOAUTH_RELEASE_TEST_COMMIT="${TEST_COMMIT}" \
  "${CANDIDATE_VERIFIER}" --existing "${AMBIGUOUS}"
assert_contains "${TEMP_DIR}/ambiguous.out" "exactly three flat entries, found 4" \
  "ambiguous candidate entry must fail specifically"

MUTATED="${TEMP_DIR}/mutated-candidate"
copy_candidate "${VALID_CANDIDATE}" "${MUTATED}"
printf 'x' >>"${MUTATED}/${JAR_NAME}"
run_expect_failure "${TEMP_DIR}/mutated.out" env \
  VELOAUTH_RELEASE_ARTIFACT_TEST_MODE=true VELOAUTH_RELEASE_TEST_COMMIT="${TEST_COMMIT}" \
  "${CANDIDATE_VERIFIER}" --existing "${MUTATED}"
assert_contains "${TEMP_DIR}/mutated.out" "checksum sidecar is non-canonical or does not match" \
  "one-byte artifact mutation must fail checksum verification"

MALFORMED_CHECKSUM="${TEMP_DIR}/malformed-checksum"
copy_candidate "${VALID_CANDIDATE}" "${MALFORMED_CHECKSUM}"
printf '%s\n%s\n' "${VALID_SHA}" "${VALID_SHA}" \
  >"${MALFORMED_CHECKSUM}/${JAR_NAME}.sha256"
run_expect_failure "${TEMP_DIR}/malformed-checksum.out" env \
  VELOAUTH_RELEASE_ARTIFACT_TEST_MODE=true VELOAUTH_RELEASE_TEST_COMMIT="${TEST_COMMIT}" \
  "${CANDIDATE_VERIFIER}" --existing "${MALFORMED_CHECKSUM}"
assert_contains "${TEMP_DIR}/malformed-checksum.out" "checksum sidecar is non-canonical" \
  "malformed checksum must fail specifically"

MALFORMED_MANIFEST="${TEMP_DIR}/malformed-manifest"
copy_candidate "${VALID_CANDIDATE}" "${MALFORMED_MANIFEST}"
printf '{not-json}\n' >"${MALFORMED_MANIFEST}/${JAR_NAME}.manifest.json"
run_expect_failure "${TEMP_DIR}/malformed-manifest.out" env \
  VELOAUTH_RELEASE_ARTIFACT_TEST_MODE=true VELOAUTH_RELEASE_TEST_COMMIT="${TEST_COMMIT}" \
  "${CANDIDATE_VERIFIER}" --existing "${MALFORMED_MANIFEST}"
assert_contains "${TEMP_DIR}/malformed-manifest.out" "Unreadable release manifest" \
  "malformed manifest must fail specifically"

NONCANONICAL_MANIFEST="${TEMP_DIR}/noncanonical-manifest"
copy_candidate "${VALID_CANDIDATE}" "${NONCANONICAL_MANIFEST}"
python3 - "${NONCANONICAL_MANIFEST}/${JAR_NAME}.manifest.json" <<'PY'
import json
import pathlib
import sys
path = pathlib.Path(sys.argv[1])
path.write_text(json.dumps(json.loads(path.read_text()), sort_keys=True) + "\n", encoding="utf-8")
PY
run_expect_failure "${TEMP_DIR}/noncanonical-manifest.out" env \
  VELOAUTH_RELEASE_ARTIFACT_TEST_MODE=true VELOAUTH_RELEASE_TEST_COMMIT="${TEST_COMMIT}" \
  "${CANDIDATE_VERIFIER}" --existing "${NONCANONICAL_MANIFEST}"
assert_contains "${TEMP_DIR}/noncanonical-manifest.out" "JSON encoding is not canonical" \
  "non-canonical manifest encoding must fail specifically"

for key in artifact buildCommand channel commit jdk maven outputTimestamp repository runId \
    schemaVersion sha256 version workflow; do
  MISMATCH_DIR="${TEMP_DIR}/mismatch-${key}"
  copy_candidate "${VALID_CANDIDATE}" "${MISMATCH_DIR}"
  python3 - "${MISMATCH_DIR}/${JAR_NAME}.manifest.json" "${key}" "${FOREIGN_VERSION}" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
key = sys.argv[2]
manifest = json.loads(path.read_text(encoding="utf-8"))
mutations = {
    "artifact": "other.jar",
    "buildCommand": "mvn package",
    "channel": "tag",
    "commit": "f" * 40,
    "jdk": "Other JDK",
    "maven": "Apache Maven 3.9.15",
    "outputTimestamp": "2026-08-11T00:00:01Z",
    "repository": "other/repository",
    "runId": "1",
    "schemaVersion": "1",
    "sha256": "0" * 64,
    "version": sys.argv[3],
    "workflow": "other",
}
manifest[key] = mutations[key]
path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
  run_expect_failure "${TEMP_DIR}/mismatch-${key}.out" env \
    VELOAUTH_RELEASE_ARTIFACT_TEST_MODE=true VELOAUTH_RELEASE_TEST_COMMIT="${TEST_COMMIT}" \
    "${CANDIDATE_VERIFIER}" --existing "${MISMATCH_DIR}"
  assert_contains "${TEMP_DIR}/mismatch-${key}.out" \
    "schema or values do not match the canonical candidate" \
    "manifest mismatch for ${key} must fail"
done

# A downloaded tag candidate is verifiable offline with an explicit tag; CI metadata, when
# present, is an additional equality check rather than a requirement for local verification.
TAG_CANDIDATE="${TEMP_DIR}/tag-candidate"
copy_candidate "${VALID_CANDIDATE}" "${TAG_CANDIDATE}"
HEAD_COMMIT="$(git -C "${PROJECT_DIR}" rev-parse HEAD)"
python3 - "${TAG_CANDIDATE}/${JAR_NAME}.manifest.json" \
  "${VALID_SHA}" "${HEAD_COMMIT}" "${JAR_NAME}" "${VERSION}" "${TAG}" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
manifest = {
    "artifact": sys.argv[4],
    "buildCommand": "./mvnw -B -V clean verify pmd:cpd-check -DskipTests=false",
    "channel": "tag",
    "commit": sys.argv[3],
    "jdk": "Eclipse Temurin 21.0.12+8",
    "maven": "Apache Maven 3.9.16",
    "outputTimestamp": "2026-08-11T00:00:00Z",
    "repository": "rafalohaki/VeloAuth",
    "runId": "123456789",
    "schemaVersion": 1,
    "sha256": sys.argv[2],
    "version": sys.argv[5],
    "workflow": "rafalohaki/VeloAuth/.github/workflows/build-and-release.yml@refs/tags/" + sys.argv[6],
}
path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
without_ci_metadata \
  VELOAUTH_RELEASE_ARTIFACT_TEST_MODE=true VELOAUTH_RELEASE_TEST_CHANNEL=tag \
  VELOAUTH_RELEASE_TEST_IDENTITY="${EXISTING_IDENTITY}" \
  "${CANDIDATE_VERIFIER}" --existing "${TAG_CANDIDATE}" "${TAG}" \
  >"${TEMP_DIR}/tag-existing.out" 2>&1 \
  || fail "downloaded tag candidate must be verifiable without live GitHub metadata"

NON_ASCII_RUN_ID="${TEMP_DIR}/non-ascii-run-id"
copy_candidate "${TAG_CANDIDATE}" "${NON_ASCII_RUN_ID}"
python3 - "${NON_ASCII_RUN_ID}/${JAR_NAME}.manifest.json" <<'PY'
import json
import pathlib
import sys
path = pathlib.Path(sys.argv[1])
manifest = json.loads(path.read_text(encoding="utf-8"))
manifest["runId"] = "１２３"
path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
run_expect_failure "${TEMP_DIR}/non-ascii-run-id.out" \
  without_ci_metadata VELOAUTH_RELEASE_ARTIFACT_TEST_MODE=true \
  VELOAUTH_RELEASE_TEST_CHANNEL=tag \
  VELOAUTH_RELEASE_TEST_IDENTITY="${EXISTING_IDENTITY}" \
  "${CANDIDATE_VERIFIER}" --existing "${NON_ASCII_RUN_ID}" "${TAG}"
assert_contains "${TEMP_DIR}/non-ascii-run-id.out" "runId must be a decimal string" \
  "release runId must use ASCII decimal digits only"

run_expect_failure "${TEMP_DIR}/tag-ci-mismatch.out" env \
  VELOAUTH_RELEASE_ARTIFACT_TEST_MODE=true VELOAUTH_RELEASE_TEST_CHANNEL=tag \
  VELOAUTH_RELEASE_TEST_IDENTITY="${EXISTING_IDENTITY}" \
  GITHUB_ACTIONS=true GITHUB_REPOSITORY=rafalohaki/VeloAuth \
  GITHUB_REF=refs/tags/${TAG} GITHUB_WORKFLOW_REF=rafalohaki/VeloAuth/.github/workflows/build-and-release.yml@refs/tags/${TAG} \
  GITHUB_RUN_ID=123456789 GITHUB_SHA=ffffffffffffffffffffffffffffffffffffffff \
  "${CANDIDATE_VERIFIER}" --existing "${TAG_CANDIDATE}" ${TAG}
assert_contains "${TEMP_DIR}/tag-ci-mismatch.out" "GITHUB_SHA" \
  "CI verification must bind the manifest to the live source commit"

# Test-only metadata and orchestration hooks cannot leak into production mode.
GUARD_CANDIDATE="${TEMP_DIR}/guard-candidate"
mkdir -p "${GUARD_CANDIDATE}"
printf 'guard\n' >"${GUARD_CANDIDATE}/${JAR_NAME}"
run_expect_failure "${TEMP_DIR}/manifest-guard.out" env \
  VELOAUTH_RELEASE_TEST_COMMIT="${TEST_COMMIT}" \
  "${MANIFEST_CREATOR}" "${GUARD_CANDIDATE}/${JAR_NAME}"
assert_contains "${TEMP_DIR}/manifest-guard.out" \
  "Test-only manifest override requires VELOAUTH_RELEASE_ARTIFACT_TEST_MODE=true" \
  "manifest test metadata must be guarded"
run_expect_failure "${TEMP_DIR}/existing-identity-guard.out" \
  without_ci_metadata VELOAUTH_RELEASE_TEST_IDENTITY="${EXISTING_IDENTITY}" \
  "${CANDIDATE_VERIFIER}" --existing "${TAG_CANDIDATE}" "${TAG}"
assert_contains "${TEMP_DIR}/existing-identity-guard.out" \
  "Test-only release override requires VELOAUTH_RELEASE_ARTIFACT_TEST_MODE=true" \
  "--existing identity test helper must be guarded"

FAKE_BUILDER="${TEMP_DIR}/fake-builder.sh"
FAKE_REPRO="${TEMP_DIR}/fake-repro.sh"
FAKE_SMOKE_A="${TEMP_DIR}/fake-smoke-a.sh"
FAKE_SMOKE_B="${TEMP_DIR}/fake-smoke-b.sh"
FAKE_IDENTITY="${TEMP_DIR}/fake-identity.sh"
cat >"${FAKE_BUILDER}" <<SH
#!/usr/bin/env bash
set -euo pipefail
build_dir=\$1
log=\$2
[[ -d "\${build_dir}" && -z "\$(find "\${build_dir}" -mindepth 1 -print -quit)" ]]
[[ "\${MAVEN_SKIP_RC:-}" == true ]]
[[ "\${MAVEN_USER_HOME:-}" == */maven-user-home ]]
[[ -f "\${VELOAUTH_RELEASE_MAVEN_SETTINGS:-}" ]]
[[ -d "\${VELOAUTH_RELEASE_MAVEN_REPOSITORY:-}" ]]
printf 'build:%s\n' "\${build_dir}" >>"\${log}"
mkdir -p "\${build_dir}/target"
printf 'one canonical build\n' >"\${build_dir}/target/${JAR_NAME}"
SH
cat >"${FAKE_REPRO}" <<SH
#!/usr/bin/env bash
set -euo pipefail
[[ "\$1" == "--compare-existing" ]]
[[ "\$2" == /*/${JAR_NAME} && -f "\$2" ]]
grep -Fxq 'one canonical build' "\$2"
printf 'repro:%s\n' "\$2" >>"\${VELOAUTH_RELEASE_TEST_INVOCATION_LOG}"
SH
cat >"${FAKE_SMOKE_A}" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
[[ "${VELOAUTH_PLUGIN_JAR:-}" == /* && -f "${VELOAUTH_PLUGIN_JAR}" ]]
task_root="$(dirname -- "${MAVEN_USER_HOME}")"
if [[ "${VELOAUTH_SMOKE_MAVEN_SETTINGS:-}" != "${task_root}/maven-settings.xml" \
    || "${VELOAUTH_SMOKE_MAVEN_REPOSITORY:-}" != "${task_root}/maven-repository" \
    || "${VELOAUTH_SMOKE_MAVEN_SETTINGS:-}" != "${VELOAUTH_RELEASE_MAVEN_SETTINGS:-}" \
    || "${VELOAUTH_SMOKE_MAVEN_REPOSITORY:-}" != "${VELOAUTH_RELEASE_MAVEN_REPOSITORY:-}" \
    || ! -f "${VELOAUTH_SMOKE_MAVEN_SETTINGS:-}" \
    || ! -d "${VELOAUTH_SMOKE_MAVEN_REPOSITORY:-}" ]]; then
  echo "smoke A did not receive the task-owned Maven settings and repository" >&2
  exit 91
fi
printf 'smoke-a:%s\n' "${VELOAUTH_PLUGIN_JAR}" >>"${VELOAUTH_RELEASE_TEST_INVOCATION_LOG}"
SH
cat >"${FAKE_SMOKE_B}" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
[[ "${VELOAUTH_PLUGIN_JAR:-}" == /* && -f "${VELOAUTH_PLUGIN_JAR}" ]]
task_root="$(dirname -- "${MAVEN_USER_HOME}")"
if [[ "${VELOAUTH_SMOKE_MAVEN_SETTINGS:-}" != "${task_root}/maven-settings.xml" \
    || "${VELOAUTH_SMOKE_MAVEN_REPOSITORY:-}" != "${task_root}/maven-repository" \
    || "${VELOAUTH_SMOKE_MAVEN_SETTINGS:-}" != "${VELOAUTH_RELEASE_MAVEN_SETTINGS:-}" \
    || "${VELOAUTH_SMOKE_MAVEN_REPOSITORY:-}" != "${VELOAUTH_RELEASE_MAVEN_REPOSITORY:-}" \
    || ! -f "${VELOAUTH_SMOKE_MAVEN_SETTINGS:-}" \
    || ! -d "${VELOAUTH_SMOKE_MAVEN_REPOSITORY:-}" ]]; then
  echo "smoke B did not receive the task-owned Maven settings and repository" >&2
  exit 92
fi
printf 'smoke-b:%s\n' "${VELOAUTH_PLUGIN_JAR}" >>"${VELOAUTH_RELEASE_TEST_INVOCATION_LOG}"
SH
cat >"${FAKE_IDENTITY}" <<SH
#!/usr/bin/env bash
set -euo pipefail
[[ "\$1" == "${TAG}" ]]
[[ "\$2" == /*/${JAR_NAME} && -f "\$2" ]]
printf 'identity:%s\n' "\$2" >>"\${VELOAUTH_RELEASE_TEST_INVOCATION_LOG}"
SH
chmod 700 "${FAKE_BUILDER}" "${FAKE_REPRO}" "${FAKE_SMOKE_A}" "${FAKE_SMOKE_B}" \
  "${FAKE_IDENTITY}"

run_expect_failure "${TEMP_DIR}/build-hook-guard.out" \
  "${CANDIDATE_VERIFIER}" --test-build "${TEMP_DIR}/unused" \
  "${FAKE_BUILDER}" "${FAKE_REPRO}" "${FAKE_SMOKE_A}" "${FAKE_SMOKE_B}" "${FAKE_IDENTITY}" \
  "${TEMP_DIR}/unused.log"
assert_contains "${TEMP_DIR}/build-hook-guard.out" \
  "Test-only release build hook requires VELOAUTH_RELEASE_ARTIFACT_TEST_MODE=true" \
  "fake build hook must be guarded"

ORCHESTRATED="${TEMP_DIR}/orchestrated-candidate"
INVOCATION_LOG="${TEMP_DIR}/orchestrated.log"
CLEANUP_PARENT="${TEMP_DIR}/cleanup-parent"
mkdir -p "${ORCHESTRATED}" "${CLEANUP_PARENT}/unrelated-sibling"
printf 'keep\n' >"${CLEANUP_PARENT}/unrelated-sibling/marker"
TMPDIR="${CLEANUP_PARENT}" VELOAUTH_RELEASE_ARTIFACT_TEST_MODE=true \
VELOAUTH_RELEASE_TEST_COMMIT="${TEST_COMMIT}" \
  "${CANDIDATE_VERIFIER}" --test-build "${ORCHESTRATED}" \
  "${FAKE_BUILDER}" "${FAKE_REPRO}" "${FAKE_SMOKE_A}" "${FAKE_SMOKE_B}" "${FAKE_IDENTITY}" \
  "${INVOCATION_LOG}" \
  >"${TEMP_DIR}/orchestrated.out" 2>&1 \
  || {
    cat "${TEMP_DIR}/orchestrated.out" >&2
    fail "guarded fake build orchestration must pass"
  }
[[ "$(grep -c '^build:' "${INVOCATION_LOG}")" == 1 ]] \
  || fail "canonical candidate must be built exactly once"
EXPECTED_ORCHESTRATED_JAR="${ORCHESTRATED}/${JAR_NAME}"
[[ "$(grep -c "^repro:${EXPECTED_ORCHESTRATED_JAR}$" "${INVOCATION_LOG}")" == 1 ]] \
  || fail "both fresh reproducibility builds must be compared to the canonical candidate"
[[ "$(grep -Ec "^smoke-[ab]:${EXPECTED_ORCHESTRATED_JAR}$" "${INVOCATION_LOG}")" == 2 ]] \
  || fail "both smokes must receive the same absolute candidate JAR"
[[ "$(grep -c "^identity:${EXPECTED_ORCHESTRATED_JAR}$" "${INVOCATION_LOG}")" == 1 ]] \
  || fail "Task5 release identity must verify the same absolute candidate exactly once"
BUILD_DIR="$(sed -n 's/^build://p' "${INVOCATION_LOG}")"
[[ -n "${BUILD_DIR}" && ! -e "${BUILD_DIR}" ]] \
  || fail "verifier-owned fake build directory must be cleaned"
[[ -f "${CLEANUP_PARENT}/unrelated-sibling/marker" ]] \
  || fail "verifier cleanup removed an unrelated sibling"
if find "${CLEANUP_PARENT}" -mindepth 1 -maxdepth 1 -type d \
    -name 'veloauth-release-candidate.*' -print -quit | grep -q .; then
  fail "verifier-owned temporary directory survived successful cleanup"
fi
LINES_BEFORE_EXISTING="$(wc -l <"${INVOCATION_LOG}" | tr -d '[:space:]')"
VELOAUTH_RELEASE_ARTIFACT_TEST_MODE=true VELOAUTH_RELEASE_TEST_COMMIT="${TEST_COMMIT}" \
VELOAUTH_RELEASE_TEST_IDENTITY="${EXISTING_IDENTITY}" \
  "${CANDIDATE_VERIFIER}" --existing "${ORCHESTRATED}" >/dev/null
[[ "$(wc -l <"${INVOCATION_LOG}" | tr -d '[:space:]')" == "${LINES_BEFORE_EXISTING}" ]] \
  || fail "--existing must execute zero builds and zero smokes"

ENV_CANDIDATE="${TEMP_DIR}/environment-candidate"
mkdir -p "${ENV_CANDIDATE}"
PRODUCTION_OVERRIDE_VARIABLES=(
  MAVEN_OPTS
  VELOAUTH_PLUGIN_JAR
  VELOAUTH_CTD_REQUIRE_PINNED_JAVA25
  VELOAUTH_EXPECTED_RUNTIME_VERSION
  VELOAUTH_SMOKE_COPY_DESTINATION
  VELOAUTH_SMOKE_COPY_TEST_MODE
  VELOAUTH_SMOKE_JAVA
  VELOAUTH_SMOKE_MAVEN_REPOSITORY
  VELOAUTH_SMOKE_MAVEN_SETTINGS
  VELOAUTH_TEST_FORWARDING_MODE
  VELOAUTH_TEST_RUNTIME_UPDATE
  VELOAUTH_VELOCITY_LABEL
  VELOAUTH_VELOCITY_SHA256
  VELOAUTH_VELOCITY_URL
)
for variable_name in "${PRODUCTION_OVERRIDE_VARIABLES[@]}"; do
  environment_log="${TEMP_DIR}/environment-${variable_name}.log"
  run_expect_failure "${TEMP_DIR}/environment-${variable_name}.out" env \
    VELOAUTH_RELEASE_ARTIFACT_TEST_MODE=true "${variable_name}=fixture-override" \
    "${CANDIDATE_VERIFIER}" --test-build "${ENV_CANDIDATE}" \
    "${FAKE_BUILDER}" "${FAKE_REPRO}" "${FAKE_SMOKE_A}" "${FAKE_SMOKE_B}" \
    "${FAKE_IDENTITY}" "${environment_log}"
  assert_contains "${TEMP_DIR}/environment-${variable_name}.out" \
    "Build-affecting environment variable must be empty or unset: ${variable_name}" \
    "ambient ${variable_name} override must fail before building"
  [[ ! -e "${environment_log}" ]] || fail "rejected ${variable_name} reached fake builder"
done

MISMATCH_REPRO="${TEMP_DIR}/mismatch-repro.sh"
cat >"${MISMATCH_REPRO}" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
printf 'repro-mismatch:%s\n' "$2" >>"${VELOAUTH_RELEASE_TEST_INVOCATION_LOG}"
echo 'Canonical candidate differs from fresh reproducibility Build A' >&2
exit 1
SH
chmod 700 "${MISMATCH_REPRO}"
REPRO_MISMATCH_CANDIDATE="${TEMP_DIR}/repro-mismatch-candidate"
mkdir -p "${REPRO_MISMATCH_CANDIDATE}"
run_expect_failure "${TEMP_DIR}/repro-mismatch.out" env \
  VELOAUTH_RELEASE_ARTIFACT_TEST_MODE=true \
  "${CANDIDATE_VERIFIER}" --test-build "${REPRO_MISMATCH_CANDIDATE}" \
  "${FAKE_BUILDER}" "${MISMATCH_REPRO}" "${FAKE_SMOKE_A}" "${FAKE_SMOKE_B}" \
  "${FAKE_IDENTITY}" "${TEMP_DIR}/repro-mismatch.log"
assert_contains "${TEMP_DIR}/repro-mismatch.out" \
  "Canonical candidate differs from fresh reproducibility Build A" \
  "candidate/repro mismatch must fail closed"
if grep -Eq '^(smoke-|identity:)' "${TEMP_DIR}/repro-mismatch.log"; then
  fail "release smoke or identity ran after reproducibility mismatch"
fi

MUTATING_SMOKE="${TEMP_DIR}/mutating-smoke.sh"
cat >"${MUTATING_SMOKE}" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
printf 'mutation' >>"${VELOAUTH_PLUGIN_JAR}"
printf 'mutating-smoke:%s\n' "${VELOAUTH_PLUGIN_JAR}" \
  >>"${VELOAUTH_RELEASE_TEST_INVOCATION_LOG}"
SH
chmod 700 "${MUTATING_SMOKE}"
MUTATION_CANDIDATE="${TEMP_DIR}/smoke-mutation-candidate"
mkdir -p "${MUTATION_CANDIDATE}"
run_expect_failure "${TEMP_DIR}/smoke-mutation.out" env \
  VELOAUTH_RELEASE_ARTIFACT_TEST_MODE=true \
  "${CANDIDATE_VERIFIER}" --test-build "${MUTATION_CANDIDATE}" \
  "${FAKE_BUILDER}" "${FAKE_REPRO}" "${MUTATING_SMOKE}" "${FAKE_SMOKE_B}" "${FAKE_IDENTITY}" \
  "${TEMP_DIR}/mutation.log"
assert_contains "${TEMP_DIR}/smoke-mutation.out" \
  "Release candidate changed during the first smoke test" \
  "smoke-time artifact mutation must fail before manifest publication"

MUTATING_IDENTITY="${TEMP_DIR}/mutating-identity.sh"
cat >"${MUTATING_IDENTITY}" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
printf 'identity:%s\n' "$2" >>"${VELOAUTH_RELEASE_TEST_INVOCATION_LOG}"
printf 'mutation' >>"$2"
SH
chmod 700 "${MUTATING_IDENTITY}"
IDENTITY_MUTATION_CANDIDATE="${TEMP_DIR}/identity-mutation-candidate"
mkdir -p "${IDENTITY_MUTATION_CANDIDATE}"
run_expect_failure "${TEMP_DIR}/identity-mutation.out" env \
  VELOAUTH_RELEASE_ARTIFACT_TEST_MODE=true \
  "${CANDIDATE_VERIFIER}" --test-build "${IDENTITY_MUTATION_CANDIDATE}" \
  "${FAKE_BUILDER}" "${FAKE_REPRO}" "${FAKE_SMOKE_A}" "${FAKE_SMOKE_B}" "${MUTATING_IDENTITY}" \
  "${TEMP_DIR}/identity-mutation.log"
assert_contains "${TEMP_DIR}/identity-mutation.out" \
  "Release candidate changed during release identity verification" \
  "identity-time artifact mutation must fail the final candidate re-hash"

# Manifest publication re-hashes the JAR and rejects a concurrent byte change.
HASH_BIN="${TEMP_DIR}/hash-bin"
mkdir -p "${HASH_BIN}"
cat >"${HASH_BIN}/sha256sum" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
count=0
[[ ! -f "${VELOAUTH_HASH_CALLS}" ]] || count="$(cat "${VELOAUTH_HASH_CALLS}")"
count=$((count + 1))
printf '%s\n' "${count}" >"${VELOAUTH_HASH_CALLS}"
if [[ "${count}" == 2 ]]; then
  printf 'x' >>"$1"
fi
/usr/bin/shasum -a 256 "$1"
SH
chmod 700 "${HASH_BIN}/sha256sum"
RACE_CANDIDATE="${TEMP_DIR}/race-candidate"
mkdir -p "${RACE_CANDIDATE}"
printf 'race\n' >"${RACE_CANDIDATE}/${JAR_NAME}"
run_expect_failure "${TEMP_DIR}/race.out" env \
  PATH="${HASH_BIN}:${PATH}" VELOAUTH_HASH_CALLS="${TEMP_DIR}/hash-calls" \
  VELOAUTH_RELEASE_ARTIFACT_TEST_MODE=true \
  "${MANIFEST_CREATOR}" "${RACE_CANDIDATE}/${JAR_NAME}"
assert_contains "${TEMP_DIR}/race.out" \
  "Release artifact changed while its metadata was being created" \
  "manifest producer must re-hash before publishing metadata"
[[ ! -e "${RACE_CANDIDATE}/${JAR_NAME}.sha256" \
    && ! -e "${RACE_CANDIDATE}/${JAR_NAME}.manifest.json" ]] \
  || fail "failed manifest publication left partial metadata"

# The guarded copy seam proves explicit absolute JAR selection happens before Maven discovery.
FAKE_BIN="${TEMP_DIR}/fake-maven-bin"
mkdir -p "${FAKE_BIN}"
cat >"${FAKE_BIN}/mvnd" <<'SH'
#!/usr/bin/env bash
printf 'maven-discovered\n' >>"${VELOAUTH_MAVEN_DISCOVERY_LOG}"
exit 99
SH
chmod 700 "${FAKE_BIN}/mvnd"
SMOKE_SOURCE="${TEMP_DIR}/explicit-plugin.jar"
printf 'explicit plugin\n' >"${SMOKE_SOURCE}"
SMOKE_SOURCE_SHA="$(sha256_file "${SMOKE_SOURCE}")"
for smoke in "${EMBEDDED_SMOKE}" "${CTD_SMOKE}"; do
  smoke_name="$(basename -- "${smoke}")"
  destination="${TEMP_DIR}/${smoke_name}.copied.jar"
  discovery_log="${TEMP_DIR}/${smoke_name}.maven.log"
  PATH="${FAKE_BIN}:${PATH}" VELOAUTH_MAVEN_DISCOVERY_LOG="${discovery_log}" \
  VELOAUTH_SMOKE_COPY_TEST_MODE=true VELOAUTH_PLUGIN_JAR="${SMOKE_SOURCE}" \
  VELOAUTH_SMOKE_COPY_DESTINATION="${destination}" "${smoke}" \
    >"${TEMP_DIR}/${smoke_name}.out" 2>&1 \
    || fail "copy-only fixture failed for ${smoke_name}"
  [[ -f "${destination}" && "$(sha256_file "${destination}")" == "${SMOKE_SOURCE_SHA}" ]] \
    || fail "copy-only fixture did not preserve explicit artifact for ${smoke_name}"
  [[ ! -e "${discovery_log}" ]] \
    || fail "${smoke_name} discovered Maven before completing explicit copy-only fixture"
done
run_expect_failure "${TEMP_DIR}/copy-guard.out" env \
  VELOAUTH_PLUGIN_JAR="${SMOKE_SOURCE}" \
  VELOAUTH_SMOKE_COPY_DESTINATION="${TEMP_DIR}/unguarded-copy.jar" "${EMBEDDED_SMOKE}"
assert_contains "${TEMP_DIR}/copy-guard.out" \
  "requires VELOAUTH_SMOKE_COPY_TEST_MODE=true" \
  "copy-only smoke destination must be guarded"
WRONG_CTD_JAVA="${TEMP_DIR}/wrong-ctd-java"
mkdir -p "${WRONG_CTD_JAVA}/bin"
cat >"${WRONG_CTD_JAVA}/bin/java" <<'SH'
#!/usr/bin/env bash
cat >&2 <<'PROPERTIES'
    java.version = 21.0.12
    java.runtime.version = 21.0.12+8-LTS
    java.vendor = Eclipse Adoptium
    java.vendor.version = Temurin-21.0.12+8
PROPERTIES
SH
chmod 700 "${WRONG_CTD_JAVA}/bin/java"
run_expect_failure "${TEMP_DIR}/wrong-ctd-java.out" env \
  VELOAUTH_CTD_REQUIRE_PINNED_JAVA25=true \
  VELOAUTH_CTD_JAVA25_HOME="${WRONG_CTD_JAVA}" \
  VELOAUTH_SMOKE_COPY_TEST_MODE=true VELOAUTH_PLUGIN_JAR="${SMOKE_SOURCE}" \
  VELOAUTH_SMOKE_COPY_DESTINATION="${TEMP_DIR}/wrong-ctd-java-copy.jar" \
  "${CTD_SMOKE}"
assert_contains "${TEMP_DIR}/wrong-ctd-java.out" \
  "must be exact Temurin 25.0.4+7" \
  "Velocity-CTD must reject a non-pinned proxy JDK before smoke execution"
python3 - "${EMBEDDED_SMOKE}" <<'PY'
import pathlib
import sys

source = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
wrapper = source.find('if [[ -x "${PROJECT_DIR}/mvnw" ]]')
daemon = source.find('elif command -v mvnd')
fallback = source.find('elif command -v mvn ')
if min(wrapper, daemon, fallback) < 0 or not wrapper < daemon < fallback:
    raise SystemExit("TEST FAILURE: smoke Maven selection must prefer checked-in ./mvnw")
PY

# Release notes are rendered deterministically and cannot expose template placeholders.
NOTES_TEMPLATE="${TEMP_DIR}/notes-template.md"
NOTES_CHANGELOG="${TEMP_DIR}/notes-changelog.md"
NOTES_A="${TEMP_DIR}/notes-a.md"
NOTES_B="${TEMP_DIR}/notes-b.md"
printf '# VeloAuth {{VERSION}}\n\n{{CHANGELOG}}\n\nVersion {{VERSION}}\n' >"${NOTES_TEMPLATE}"
# Keep-a-Changelog fixture with a neighbouring version, so the assertions below prove the
# renderer emits exactly one section instead of the whole file.
{
  printf '# Changelog\n\n'
  printf '## [%s] - 2026-08-16\n\n' "${VERSION}"
  printf '%s\n' '- Fixed one thing.' '- Fixed another thing.'
  printf '\n## [%s] - 2026-08-11\n\n' "${FOREIGN_VERSION}"
  printf '%s\n' '- Older release detail that must not leak.'
} >"${NOTES_CHANGELOG}"
"${CANDIDATE_VERIFIER}" --render-notes "${NOTES_TEMPLATE}" "${NOTES_CHANGELOG}" \
  "${NOTES_A}" "${VERSION}"
"${CANDIDATE_VERIFIER}" --render-notes "${NOTES_TEMPLATE}" "${NOTES_CHANGELOG}" \
  "${NOTES_B}" "${VERSION}"
cmp -s "${NOTES_A}" "${NOTES_B}" || fail "release-note rendering must be deterministic"
if grep -Eq '{{[^{}]+}}' "${NOTES_A}"; then
  fail "rendered release notes contain a literal placeholder"
fi
assert_contains "${NOTES_A}" "# VeloAuth ${VERSION}" "release-note version was not rendered"
assert_contains "${NOTES_A}" "- Fixed another thing." "release changelog was not rendered"
# Only the released version's section may appear: neither the neighbouring section's body
# nor any '## [' heading from the changelog belongs in a single release's notes.
if grep -Fq 'Older release detail that must not leak.' "${NOTES_A}"; then
  fail "release notes must not include another version's changelog section"
fi
if grep -Eq '^## \[' "${NOTES_A}"; then
  fail "release notes must not repeat changelog version headings"
fi

# A version with no changelog section must stop the release instead of publishing empty notes.
UNDOCUMENTED_CHANGELOG="${TEMP_DIR}/undocumented-changelog.md"
printf '# Changelog\n\n## [%s] - 2026-08-11\n\n- Only the other version is documented.\n' \
  "${FOREIGN_VERSION}" >"${UNDOCUMENTED_CHANGELOG}"
run_expect_failure "${TEMP_DIR}/undocumented-notes.out" "${CANDIDATE_VERIFIER}" \
  --render-notes "${NOTES_TEMPLATE}" "${UNDOCUMENTED_CHANGELOG}" \
  "${TEMP_DIR}/undocumented-rendered.md" "${VERSION}"
assert_contains "${TEMP_DIR}/undocumented-notes.out" "has no '## [${VERSION}]' section" \
  "releasing a version with no changelog section must fail"

# An empty section is as undocumented as a missing one.
EMPTY_SECTION_CHANGELOG="${TEMP_DIR}/empty-section-changelog.md"
printf '# Changelog\n\n## [%s] - 2026-08-16\n\n## [%s] - 2026-08-11\n\n- Older.\n' \
  "${VERSION}" "${FOREIGN_VERSION}" >"${EMPTY_SECTION_CHANGELOG}"
run_expect_failure "${TEMP_DIR}/empty-section.out" "${CANDIDATE_VERIFIER}" \
  --render-notes "${NOTES_TEMPLATE}" "${EMPTY_SECTION_CHANGELOG}" \
  "${TEMP_DIR}/empty-section-rendered.md" "${VERSION}"
assert_contains "${TEMP_DIR}/empty-section.out" "is empty" \
  "an empty changelog section must fail"

ACTUAL_NOTES="${TEMP_DIR}/actual-release-notes.md"
"${CANDIDATE_VERIFIER}" --render-notes "${RELEASE_TEMPLATE}" \
  "${PROJECT_DIR}/CHANGELOG.md" "${ACTUAL_NOTES}" "${VERSION}"
if grep -Eq '{{[^{}]+}}' "${ACTUAL_NOTES}"; then
  fail "actual release template leaves unresolved placeholders"
fi

BAD_NOTES_TEMPLATE="${TEMP_DIR}/bad-notes-template.md"
printf '{{VERSION}}\n{{CHANGELOG}}\n{{UNRESOLVED}}\n' >"${BAD_NOTES_TEMPLATE}"
run_expect_failure "${TEMP_DIR}/bad-notes.out" "${CANDIDATE_VERIFIER}" \
  --render-notes "${BAD_NOTES_TEMPLATE}" "${NOTES_CHANGELOG}" \
  "${TEMP_DIR}/bad-rendered.md" "${VERSION}"
assert_contains "${TEMP_DIR}/bad-notes.out" "unresolved placeholder" \
  "unresolved release-note placeholders must fail"

# Workflow topology and immutable-release controls are part of the executable contract.
python3 - "${WORKFLOW}" <<'PY' || exit 1
import pathlib
import re
import sys

text = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
required = [
    "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
    "actions/setup-java@b6effb05e454b25005698d916606bdc6ffcbf961",
    "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
    "actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c",
    "actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6",
    "environment: production-release",
    "./scripts/verify-release-candidate.sh --build",
    "./scripts/verify-release-candidate.sh --existing",
    "./scripts/verify-release-candidate.sh --render-notes",
    "./scripts/test-verify-reproducible-jar.sh",
    "gh attestation verify",
    "gh release download",
    "--json isImmutable --jq .isImmutable",
    "--signer-workflow",
    "--source-ref",
    "--source-digest",
    "--latest=true",
    "EXTERNAL_CANARY_GREEN",
    "java-version: '25.0.4+7.0.LTS'",
    "VELOAUTH_CTD_JAVA25_HOME",
    "RELEASE_POLICY_TOKEN",
    "repos/${GITHUB_REPOSITORY}/immutable-releases",
    "X-GitHub-Api-Version: 2026-03-10",
    "repos/${GITHUB_REPOSITORY}/git/ref/tags/${GITHUB_REF_NAME}",
    "repos/${GITHUB_REPOSITORY}/git/tags/",
]
for token in required:
    if token not in text:
        raise SystemExit(f"TEST FAILURE: workflow missing required token: {token}")
for job in ("verify", "candidate", "release"):
    if not re.search(rf"^  {job}:\s*$", text, re.MULTILINE):
        raise SystemExit(f"TEST FAILURE: workflow missing {job} job")
if text.count("verify-release-candidate.sh --build") != 1:
    raise SystemExit("TEST FAILURE: workflow must run exactly one canonical candidate build")
if not re.search(r"(?ms)^  release:.*?^    needs:.*candidate", text):
    raise SystemExit("TEST FAILURE: release job must depend on candidate")
if not re.search(r"(?ms)^  release:.*?actions/download-artifact@", text):
    raise SystemExit("TEST FAILURE: release job must download the candidate workflow artifact")
for forbidden in (
    "allowUpdates", "replacesArtifacts", "ncipollo/release-action", "overwrite: true",
    "$(date", "date -u",
    "actions/attest-build-provenance@",
):
    if forbidden.lower() in text.lower():
        raise SystemExit(f"TEST FAILURE: workflow contains forbidden mutable token: {forbidden}")

# In-place release mutation belongs to the rolling job and nowhere else. The versioned path
# publishes immutable artifacts, so a --clobber leaking into it would silently make an
# "immutable" release overwritable.
def job_section(name, following):
    body = text.split(f"\n  {name}:", 1)
    if len(body) != 2:
        raise SystemExit(f"TEST FAILURE: workflow is missing the {name} job")
    return body[1].split(f"\n  {following}:", 1)[0]


rolling_section = job_section("rolling", "candidate")
versioned_section = text.split("\n  candidate:", 1)[1]
for mutable_token in ("--clobber", "refs/tags/latest", "git tag -a latest"):
    if mutable_token.lower() in versioned_section.lower():
        raise SystemExit(
            f"TEST FAILURE: versioned release path must stay immutable: {mutable_token}")
if "--clobber" not in rolling_section:
    raise SystemExit("TEST FAILURE: rolling release must replace assets in place")
for rolling_token in (
    "needs: verify",
    "github.ref == 'refs/heads/main'",
    "Expected exactly one release",
):
    if rolling_token not in rolling_section:
        raise SystemExit(f"TEST FAILURE: rolling contract is missing: {rolling_token}")
if not re.search(r"(?m)^\s+pull_request:\s*$", text):
    raise SystemExit("TEST FAILURE: workflow must verify pull requests")
if "tags:" not in text or "v*" not in text:
    raise SystemExit("TEST FAILURE: workflow must create candidates only from version tags")
PY
ruby - "${WORKFLOW}" <<'RUBY' || exit 1
require "yaml"

workflow = YAML.safe_load(File.read(ARGV.fetch(0)), aliases: true)
triggers = workflow["on"] || workflow[true]
raise "TEST FAILURE: workflow trigger map is missing" unless triggers.is_a?(Hash)
push = triggers.fetch("push")
pull_request = triggers.fetch("pull_request")
raise "TEST FAILURE: main verification push trigger is missing" unless push.fetch("branches").include?("main")
raise "TEST FAILURE: release tag trigger is missing" unless push.fetch("tags").include?("v*")
raise "TEST FAILURE: pull request verification trigger is missing" unless pull_request.is_a?(Hash)

jobs = workflow.fetch("jobs")
verify = jobs.fetch("verify")
candidate = jobs.fetch("candidate")
release = jobs.fetch("release")
setup_steps = jobs.values.flat_map { |job| job.fetch("steps", []) }.select do |step|
  step.fetch("uses", "").start_with?("actions/setup-java@")
end
raise "TEST FAILURE: expected six exact setup-java steps" unless setup_steps.length == 6
setup_steps.each do |step|
  unless step.fetch("with").fetch("show-download-progress") == true
    raise "TEST FAILURE: every setup-java step must prevent inherited MAVEN_ARGS=-ntp"
  end
end
raise "TEST FAILURE: branch/PR verifier must reject tag refs" unless verify.fetch("if").include?("!startsWith")
raise "TEST FAILURE: candidate must be tag-only" unless candidate.fetch("if").include?("refs/tags/v")
raise "TEST FAILURE: release must be tag-only" unless release.fetch("if").include?("refs/tags/v")
unless release.fetch("needs").sort == ["candidate", "osv-scan"]
  raise "TEST FAILURE: release must depend only on candidate and same-run OSV admission"
end
raise "TEST FAILURE: release lacks protected environment" unless release.fetch("environment") == "production-release"

candidate_scripts = candidate.fetch("steps").map { |step| step["run"] }.compact.join("\n")
unless candidate_scripts.include?('expected_tag="v${version}"') &&
       candidate_scripts.include?('"${RELEASE_REF_NAME}" != "${expected_tag}"') &&
       candidate_scripts.include?('"$(git rev-parse HEAD)" != "${RELEASE_SHA}"')
  raise "TEST FAILURE: candidate does not bind tag, POM version, checkout, and workflow SHA"
end

candidate_steps = candidate.fetch("steps")
java25_index = candidate_steps.index { |step| step["id"] == "candidate-java25" }
java21_index = candidate_steps.index { |step| step["name"] == "Restore exact Temurin 21.0.12+8 as the build default" }
repro_index = candidate_steps.index { |step| step["name"] == "Run reproducibility fixture tests" }
build_index = candidate_steps.index { |step| step["name"] == "Build and smoke the single canonical candidate" }
attest_index = candidate_steps.index { |step| step["name"] == "Attest the exact candidate JAR" }
post_attest_index = candidate_steps.index { |step| step["name"] == "Re-hash the attested candidate before upload" }
upload_index = candidate_steps.index { |step| step["name"] == "Upload the immutable three-file candidate" }
raise "TEST FAILURE: candidate reproducibility step is missing" unless repro_index
unless java25_index < java21_index && java21_index < repro_index
  raise "TEST FAILURE: candidate must capture exact Java 25 then restore exact Java 21 before build gates"
end
build_env = candidate_steps.fetch(build_index).fetch("env")
unless build_env.fetch("VELOAUTH_CTD_JAVA25_HOME").include?("candidate-java25")
  raise "TEST FAILURE: canonical candidate does not pass the pinned Java 25 home only to CTD smoke"
end
repro_script = candidate_steps.fetch(repro_index).fetch("run")
unless repro_script.include?("./scripts/test-verify-reproducible-jar.sh")
  raise "TEST FAILURE: candidate must run reproducibility fixture gates"
end
build_script = candidate_steps.fetch(build_index).fetch("run")
unless build_script.include?("verify-release-candidate.sh --build")
  raise "TEST FAILURE: canonical build must own candidate/reproducibility comparison"
end
unless repro_index < build_index && build_index < attest_index && attest_index < post_attest_index && post_attest_index < upload_index
  raise "TEST FAILURE: candidate order must be fixture, canonical build plus comparison, attest, re-hash, upload"
end

release_steps = release.fetch("steps")
gate_index = release_steps.index { |step| step["name"] == "Enforce canary and operator approval evidence" }
publish_index = release_steps.index { |step| step["name"] == "Publish one immutable release with exactly three assets" }
release_attest_index = release_steps.index { |step| step["name"] == "Verify the exact attestation before publication" }
release_rehash_index = release_steps.index { |step| step["name"] == "Re-hash the attested candidate before publication" }
published_verify_index = release_steps.index { |step| step["name"] == "Verify immutable published assets byte for byte" }
policy_index = release_steps.index { |step| step["name"] == "Require immutable-release policy" }
raise "TEST FAILURE: protected release gate is missing" unless gate_index
raise "TEST FAILURE: immutable publication step is missing" unless publish_index
raise "TEST FAILURE: immutable-release policy gate is missing" unless policy_index
raise "TEST FAILURE: protected release gate must precede publication" unless gate_index < publish_index
unless release_attest_index < release_rehash_index && release_rehash_index < policy_index && policy_index < publish_index && publish_index < published_verify_index
  raise "TEST FAILURE: release order must be attest, re-hash, publish, immutable byte verification"
end
policy = release_steps.fetch(policy_index)
unless policy.fetch("env").fetch("GH_TOKEN") == "${{ secrets.RELEASE_POLICY_TOKEN }}" &&
       policy.fetch("run").include?("immutable-releases") &&
       policy.fetch("run").include?(".enabled")
  raise "TEST FAILURE: immutable-release policy must use the protected Administration(read) token"
end
publish_script = release_steps.fetch(publish_index).fetch("run")
unless publish_script.include?("git/ref/tags/${GITHUB_REF_NAME}") &&
       publish_script.include?("git/tags/${tag_sha}") &&
       publish_script.index("git/ref/tags/${GITHUB_REF_NAME}") < publish_script.index("gh release create")
  raise "TEST FAILURE: remote lightweight/annotated tag must be peeled immediately before publication"
end
published_script = release_steps.fetch(published_verify_index).fetch("run")
unless published_script.include?("--json isImmutable --jq .isImmutable") &&
       published_script.include?("gh release download") &&
       published_script.include?("cmp --") &&
       published_script.include?("verify-release-candidate.sh --existing") &&
       published_script.include?("git/ref/tags/${GITHUB_REF_NAME}") &&
       published_script.include?("immutable-releases") &&
       release_steps.fetch(published_verify_index).fetch("env").fetch("RELEASE_POLICY_TOKEN") ==
         "${{ secrets.RELEASE_POLICY_TOKEN }}"
  raise "TEST FAILURE: published release must be immutable and byte-identical with exactly three assets"
end
gate = release_steps.fetch(gate_index)
gate_env = gate.fetch("env")
raise "TEST FAILURE: external canary evidence is not read from protected environment" unless gate_env.key?("EXTERNAL_CANARY_GREEN")
raise "TEST FAILURE: operator signoff evidence is not read from protected environment" unless gate_env.key?("OPERATOR_RELEASE_SIGNOFF")
gate_script = gate.fetch("run")
raise "TEST FAILURE: external canary must be explicitly green" unless gate_script.include?('EXTERNAL_CANARY_GREEN}" != true')
raise "TEST FAILURE: operator signoff must bind tag and commit" unless gate_script.include?('expected_signoff="${GITHUB_REF_NAME}:${GITHUB_SHA}"')
RUBY

grep -Fq 'production-release' "${RELEASE_TEMPLATE}" \
  || fail "release template must document the protected production-release environment"
grep -Fq 'EXTERNAL_CANARY_GREEN' "${RELEASE_TEMPLATE}" \
  || fail "release template must document the external canary approval gate"
grep -Fq 'production-release' "${PROJECT_DIR}/README.md" \
  || fail "README must document the protected release environment precondition"
grep -Fq 'verify-release-candidate.sh --existing' "${PROJECT_DIR}/README.md" \
  || fail "README must document offline verification of an existing candidate"
grep -Fq 'RELEASE_POLICY_TOKEN' "${PROJECT_DIR}/README.md" \
  || fail "README must document the protected immutable-release policy token"
grep -Fq 'Administration (read)' "${PROJECT_DIR}/README.md" \
  || fail "README must document least-privilege policy-token permission"
grep -Fq 'protected tag ruleset' "${PROJECT_DIR}/README.md" \
  || fail "README must require a protected tag ruleset before tag creation"

echo "Release artifact fixture tests passed"
