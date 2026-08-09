#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
VELOCITY_URL="${VELOAUTH_VELOCITY_URL:-https://fill-data.papermc.io/v1/objects/0c3d16b70ed757638b696a9a87d670b4301f23a6fef30c3acbbd9b0e0d7b29bb/velocity-3.5.0-SNAPSHOT-609.jar}"
VELOCITY_SHA256="${VELOAUTH_VELOCITY_SHA256:-0c3d16b70ed757638b696a9a87d670b4301f23a6fef30c3acbbd9b0e0d7b29bb}"
VELOCITY_LABEL="${VELOAUTH_VELOCITY_LABEL:-Velocity 3.5}"
FORWARDING_MODE="${VELOAUTH_TEST_FORWARDING_MODE:-none}"
SMOKE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/veloauth-velocity-smoke.XXXXXX")"
CONSOLE_PIPE="${SMOKE_DIR}/console.pipe"
VELOCITY_LOG="${SMOKE_DIR}/velocity-first.log"
VELOCITY_PID=""
TEST_RUNTIME_UPDATE="${VELOAUTH_TEST_RUNTIME_UPDATE:-true}"

cleanup() {
  if [[ -n "${VELOCITY_PID}" ]] && kill -0 "${VELOCITY_PID}" 2>/dev/null; then
    printf 'shutdown\n' >&3 || true
    for _ in {1..20}; do
      if ! kill -0 "${VELOCITY_PID}" 2>/dev/null; then
        break
      fi
      sleep 0.25
    done
    if kill -0 "${VELOCITY_PID}" 2>/dev/null; then
      kill "${VELOCITY_PID}" 2>/dev/null || true
    fi
  fi
  exec 3>&- || true
  if [[ -d "${SMOKE_DIR}" && "$(basename -- "${SMOKE_DIR}")" == veloauth-velocity-smoke.* ]]; then
    rm -rf -- "${SMOKE_DIR}"
  fi
}
trap cleanup EXIT

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

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required to reserve a free local smoke-test port" >&2
  exit 1
fi

case "${FORWARDING_MODE}" in
  none|modern) ;;
  *)
    echo "Unsupported smoke-test forwarding mode: ${FORWARDING_MODE}" >&2
    exit 1
    ;;
esac

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

evaluate_maven_expression() {
  "${MAVEN[@]}" -f "${PROJECT_DIR}/pom.xml" help:evaluate \
    -Dstyle.color=never -DforceStdout -Dexpression="$1" \
    | awk 'NF && $0 !~ /^\[/ { value=$0 } END { print value }'
}

FINAL_NAME="$(evaluate_maven_expression project.build.finalName)"
PLUGIN_JAR="${VELOAUTH_PLUGIN_JAR:-${PROJECT_DIR}/target/${FINAL_NAME}.jar}"
if [[ ! -f "${PLUGIN_JAR}" ]]; then
  if [[ -n "${VELOAUTH_PLUGIN_JAR:-}" ]]; then
    echo "Requested VeloAuth plugin JAR does not exist: ${PLUGIN_JAR}" >&2
    exit 1
  fi
  "${MAVEN[@]}" -f "${PROJECT_DIR}/pom.xml" -DskipTests package
fi

mkdir -p "${SMOKE_DIR}/plugins/veloauth"
curl --fail --silent --show-error --location --max-time 60 \
  --output "${SMOKE_DIR}/velocity.jar" "${VELOCITY_URL}"
if [[ "$(sha256_file "${SMOKE_DIR}/velocity.jar")" != "${VELOCITY_SHA256}" ]]; then
  echo "Pinned Velocity smoke-test binary checksum mismatch" >&2
  exit 1
fi
cp "${PLUGIN_JAR}" "${SMOKE_DIR}/plugins/veloauth.jar"

cat >"${SMOKE_DIR}/plugins/veloauth/config.yml" <<'YAML'
premium:
  check-enabled: false
auth-server:
  mode: embedded
  timeout-seconds: 60
  embedded:
    port: 0
    max-connections: 32
    handshake-timeout-seconds: 5
    login-timeout-seconds: 10
YAML

PROXY_PORT="$(python3 - <<'PY'
import socket
with socket.socket() as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
)"

if [[ "${FORWARDING_MODE}" == modern ]]; then
  cat >"${SMOKE_DIR}/velocity.toml" <<TOML
config-version = "2.9"
bind = "127.0.0.1:${PROXY_PORT}"
online-mode = false
player-info-forwarding-mode = "modern"
forwarding-secret-file = "forwarding.secret"

[servers]
lobby = "127.0.0.1:30066"
try = ["lobby"]
TOML
  umask 077
  printf '%s\n' 'veloauth-embedded-modern-forwarding-smoke-secret' \
    >"${SMOKE_DIR}/forwarding.secret"
fi

mkfifo "${CONSOLE_PIPE}"
exec 3<>"${CONSOLE_PIPE}"

start_velocity() {
  VELOCITY_LOG="$1"
  (
    cd "${SMOKE_DIR}"
    java -Xms128m -Xmx512m -jar velocity.jar --port "${PROXY_PORT}" \
      <"${CONSOLE_PIPE}" >"${VELOCITY_LOG}" 2>&1
  ) &
  VELOCITY_PID=$!

  local ready=false
  for _ in {1..240}; do
    if grep -Fq "Ready - player connections allowed" "${VELOCITY_LOG}" 2>/dev/null; then
      ready=true
      break
    fi
    if ! kill -0 "${VELOCITY_PID}" 2>/dev/null; then
      break
    fi
    sleep 0.25
  done
  if [[ "${ready}" != true ]]; then
    echo "Velocity embedded-limbo smoke did not become ready" >&2
    tail -120 "${VELOCITY_LOG}" >&2 || true
    exit 1
  fi
}

stop_velocity() {
  printf 'shutdown\n' >&3
  wait "${VELOCITY_PID}"
  VELOCITY_PID=""
  if ! grep -Fq "VeloAuth shutdown completed successfully" "${VELOCITY_LOG}"; then
    echo "Velocity smoke did not observe a clean VeloAuth shutdown" >&2
    tail -120 "${VELOCITY_LOG}" >&2 || true
    exit 1
  fi
}

test_latest_client() {
  "${MAVEN[@]}" -q -f "${PROJECT_DIR}/pom.xml" \
    -Dtest=VelocityEmbeddedProxyIT \
    -Dveloauth.smoke.host=127.0.0.1 \
    -Dveloauth.smoke.port="${PROXY_PORT}" test
}

start_velocity "${SMOKE_DIR}/velocity-first.log"
test_latest_client

if [[ "${TEST_RUNTIME_UPDATE}" == true ]]; then
  pending=false
  for _ in {1..240}; do
    if [[ -f "${SMOKE_DIR}/plugins/veloauth/runtime/pending-runtime.properties" ]]; then
      pending=true
      break
    fi
    sleep 0.25
  done
  if [[ "${pending}" != true ]]; then
    echo "Embedded ViaVersion snapshot was not staged after startup" >&2
    tail -120 "${VELOCITY_LOG}" >&2 || true
    exit 1
  fi
  if ! grep -Fq "managed ViaVersion 5.11.0" "${VELOCITY_LOG}"; then
    echo "First startup hot-swapped or did not report the pinned runtime" >&2
    tail -120 "${VELOCITY_LOG}" >&2 || true
    exit 1
  fi

  stop_velocity
  start_velocity "${SMOKE_DIR}/velocity-second.log"
  if [[ ! -f "${SMOKE_DIR}/plugins/veloauth/runtime/active-runtime.properties" \
      || -f "${SMOKE_DIR}/plugins/veloauth/runtime/pending-runtime.properties" ]]; then
    echo "Staged ViaVersion snapshot was not promoted atomically on restart" >&2
    tail -120 "${VELOCITY_LOG}" >&2 || true
    exit 1
  fi
  if ! grep -Fq "Activated staged ViaVersion runtime" "${VELOCITY_LOG}"; then
    echo "Second startup did not report snapshot activation" >&2
    tail -120 "${VELOCITY_LOG}" >&2 || true
    exit 1
  fi
  test_latest_client

  stop_velocity
  cat >"${SMOKE_DIR}/plugins/veloauth/runtime/pending-runtime.properties" <<'PROPERTIES'
version=99.0.0-20990101.000000-1
url=https://untrusted.example/viaversion-common-99.0.0.jar
sha256=0000000000000000000000000000000000000000000000000000000000000000
PROPERTIES
  start_velocity "${SMOKE_DIR}/velocity-third.log"
  if [[ -f "${SMOKE_DIR}/plugins/veloauth/runtime/pending-runtime.properties" \
      || ! -f "${SMOKE_DIR}/plugins/veloauth/runtime/active-runtime.properties" ]]; then
    echo "Tampered pending runtime did not fall back to the active runtime" >&2
    tail -120 "${VELOCITY_LOG}" >&2 || true
    exit 1
  fi
  if ! grep -Fq "Ignoring invalid embedded protocol runtime manifest" "${VELOCITY_LOG}"; then
    echo "Third startup did not report rejection of the tampered pending manifest" >&2
    tail -120 "${VELOCITY_LOG}" >&2 || true
    exit 1
  fi
  test_latest_client
fi

stop_velocity
echo "${VELOCITY_LABEL} embedded limbo smoke passed with a Minecraft 26.2 client (${FORWARDING_MODE} forwarding)"
if [[ "${TEST_RUNTIME_UPDATE}" == true ]]; then
  echo "Embedded ViaVersion staging, restart activation and tampered-pending rollback passed"
fi
