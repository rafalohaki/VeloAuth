#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
PLUGIN_JAR_OVERRIDE="${VELOAUTH_PLUGIN_JAR:-}"
VELOCITY_URL="https://fill-data.papermc.io/v1/objects/0c3d16b70ed757638b696a9a87d670b4301f23a6fef30c3acbbd9b0e0d7b29bb/velocity-3.5.0-SNAPSHOT-609.jar"
VELOCITY_SHA256="0c3d16b70ed757638b696a9a87d670b4301f23a6fef30c3acbbd9b0e0d7b29bb"
NANOLIMBO_URL="https://github.com/Nan1t/NanoLimbo/releases/download/v1.13.0/NanoLimbo.jar"
NANOLIMBO_SHA256="884dc3d4941fb0964dfd348cebc66afb692b156a213cc980d6f47f02441432cf"
AUTH_MARKER="VELOAUTH_EXTERNAL_AUTH_V1_13_0"
BACKEND_MARKER="VELOAUTH_EXTERNAL_BACKEND_V1_13_0"
JOURNEY_USERNAME="VAuthExtCanary"
JOURNEY_PASSWORD="ExtCanary1Safe"
SMOKE_JAVA="${VELOAUTH_SMOKE_JAVA:-java}"
KEEP_WORKDIR="${VELOAUTH_EXTERNAL_KEEP_WORKDIR:-false}"
SMOKE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/veloauth-external-smoke.XXXXXX")"
VELOCITY_PID=""
AUTH_PID=""
BACKEND_PID=""

cleanup_process() {
  local pid="$1"
  local fd="$2"
  local command="$3"
  if [[ -n "${pid}" ]] && kill -0 "${pid}" 2>/dev/null; then
    printf '%s\n' "${command}" >&"${fd}" 2>/dev/null || true
    for _ in {1..40}; do
      if ! kill -0 "${pid}" 2>/dev/null; then
        return
      fi
      sleep 0.25
    done
    kill "${pid}" 2>/dev/null || true
  fi
}

cleanup() {
  cleanup_process "${VELOCITY_PID}" 5 shutdown
  cleanup_process "${AUTH_PID}" 3 stop
  cleanup_process "${BACKEND_PID}" 4 stop
  exec 3>&- 4>&- 5>&- || true
  if [[ "${KEEP_WORKDIR}" == true ]]; then
    echo "Preserved external smoke workdir: ${SMOKE_DIR}" >&2
  elif [[ -d "${SMOKE_DIR}" && "$(basename -- "${SMOKE_DIR}")" == veloauth-external-smoke.* ]]; then
    rm -rf -- "${SMOKE_DIR}"
  fi
}
trap cleanup EXIT

case "${KEEP_WORKDIR}" in
  true|false) ;;
  *)
    echo "VELOAUTH_EXTERNAL_KEEP_WORKDIR must be true or false" >&2
    exit 1
    ;;
esac

if [[ -n "${PLUGIN_JAR_OVERRIDE}" ]]; then
  if [[ "${PLUGIN_JAR_OVERRIDE}" != /* || ! -f "${PLUGIN_JAR_OVERRIDE}" \
      || -L "${PLUGIN_JAR_OVERRIDE}" ]]; then
    echo "VELOAUTH_PLUGIN_JAR must be an absolute regular non-symlink file" >&2
    exit 1
  fi
  PLUGIN_JAR="${PLUGIN_JAR_OVERRIDE}"
fi
if [[ "${SMOKE_JAVA}" == */* ]]; then
  [[ "${SMOKE_JAVA}" == /* && -x "${SMOKE_JAVA}" ]] || {
    echo "VELOAUTH_SMOKE_JAVA must be an absolute executable path" >&2
    exit 1
  }
elif ! command -v "${SMOKE_JAVA}" >/dev/null 2>&1; then
  echo "Smoke-test Java command is unavailable: ${SMOKE_JAVA}" >&2
  exit 1
fi
for command in curl unzip awk python3; do
  command -v "${command}" >/dev/null 2>&1 || {
    echo "${command} is required for the external journey" >&2
    exit 1
  }
done

if [[ -x "${PROJECT_DIR}/mvnw" ]]; then
  MAVEN=("${PROJECT_DIR}/mvnw")
elif command -v mvnd >/dev/null 2>&1; then
  MAVEN=(mvnd)
elif command -v mvn >/dev/null 2>&1; then
  MAVEN=(mvn)
else
  echo "Maven, mvnd or ./mvnw is required" >&2
  exit 1
fi

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

if [[ -z "${PLUGIN_JAR_OVERRIDE}" ]]; then
  FINAL_NAME="$(evaluate_maven_expression project.build.finalName)"
  PLUGIN_JAR="${PROJECT_DIR}/target/${FINAL_NAME}.jar"
fi
if [[ ! -f "${PLUGIN_JAR}" ]]; then
  if [[ -n "${PLUGIN_JAR_OVERRIDE}" ]]; then
    echo "Requested VeloAuth plugin JAR does not exist: ${PLUGIN_JAR}" >&2
    exit 1
  fi
  "${MAVEN[@]}" -f "${PROJECT_DIR}/pom.xml" -DskipTests package
fi
CANDIDATE_SHA256="$(sha256_file "${PLUGIN_JAR}")"

read -r PROXY_PORT AUTH_PORT BACKEND_PORT <<EOF
$(python3 - <<'PY'
import socket

sockets = []
try:
    for _ in range(3):
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        sockets.append(sock)
    print(*(sock.getsockname()[1] for sock in sockets))
finally:
    for sock in sockets:
        sock.close()
PY
)
EOF

mkdir -p "${SMOKE_DIR}/auth" "${SMOKE_DIR}/backend" \
  "${SMOKE_DIR}/velocity/plugins/veloauth" "${SMOKE_DIR}/velocity/plugins/bStats" \
  "${PROJECT_DIR}/target"
curl --proto '=https' --proto-redir '=https' --tlsv1.2 \
  --fail --silent --show-error --location --max-time 60 \
  --max-filesize 100000000 \
  --output "${SMOKE_DIR}/velocity/velocity.jar" "${VELOCITY_URL}"
curl --proto '=https' --proto-redir '=https' --tlsv1.2 \
  --fail --silent --show-error --location --max-time 60 \
  --max-filesize 100000000 \
  --output "${SMOKE_DIR}/NanoLimbo.jar" "${NANOLIMBO_URL}"
[[ "$(sha256_file "${SMOKE_DIR}/velocity/velocity.jar")" == "${VELOCITY_SHA256}" ]] || {
  echo "Pinned Velocity checksum mismatch" >&2
  exit 1
}
[[ "$(sha256_file "${SMOKE_DIR}/NanoLimbo.jar")" == "${NANOLIMBO_SHA256}" ]] || {
  echo "Pinned NanoLimbo checksum mismatch" >&2
  exit 1
}
cp "${SMOKE_DIR}/NanoLimbo.jar" "${SMOKE_DIR}/auth/NanoLimbo.jar"
cp "${SMOKE_DIR}/NanoLimbo.jar" "${SMOKE_DIR}/backend/NanoLimbo.jar"
cp "${PLUGIN_JAR}" "${SMOKE_DIR}/velocity/plugins/veloauth.jar"
cat >"${SMOKE_DIR}/velocity/plugins/bStats/config.txt" <<'YAML'
enabled: false
YAML

write_nanolimbo_config() {
  local destination="$1"
  local port="$2"
  local marker="$3"
  unzip -p "${SMOKE_DIR}/NanoLimbo.jar" settings.yml | awk \
    -v port="${port}" -v marker="${marker}" '
      !port_written && $0 == "  port: 65535" {
        print "  port: " port
        port_written = 1
        next
      }
      $0 == "  text: \"<white>Welcome to the <gradient:blue:white>NanoLimbo<white>!\"" {
        print "  text: \"<white>" marker "\""
        next
      }
      $0 == "  transportType: EPOLL" {
        print "  transportType: NIO"
        next
      }
      $0 == "logPlayersIp: true" {
        print "logPlayersIp: false"
        next
      }
      { print }
    ' >"${destination}/settings.yml"
}
write_nanolimbo_config "${SMOKE_DIR}/auth" "${AUTH_PORT}" "${AUTH_MARKER}"
write_nanolimbo_config "${SMOKE_DIR}/backend" "${BACKEND_PORT}" "${BACKEND_MARKER}"

cat >"${SMOKE_DIR}/velocity/velocity.toml" <<TOML
config-version = "2.9"
bind = "127.0.0.1:${PROXY_PORT}"
online-mode = false
player-info-forwarding-mode = "none"
forwarding-secret-file = "forwarding.secret"
show-max-players = 20

[servers]
limbo = "127.0.0.1:${AUTH_PORT}"
lobby = "127.0.0.1:${BACKEND_PORT}"
try = ["lobby"]

[forced-hosts]

[advanced]
login-ratelimit = 0
TOML
umask 077
printf '%s\n' 'veloauth-external-loopback-only-unused-secret' \
  >"${SMOKE_DIR}/velocity/forwarding.secret"

cat >"${SMOKE_DIR}/velocity/plugins/veloauth/config.yml" <<'YAML'
language: en
database:
  storage-type: H2
premium:
  check-enabled: false
auth-server:
  mode: external
  server-name: limbo
  timeout-seconds: 60
connection:
  auto-transfer-delay-ms: 1500
report:
  enabled: false
YAML

mkfifo "${SMOKE_DIR}/auth.pipe" "${SMOKE_DIR}/backend.pipe" "${SMOKE_DIR}/velocity.pipe"
exec 3<>"${SMOKE_DIR}/auth.pipe"
exec 4<>"${SMOKE_DIR}/backend.pipe"
exec 5<>"${SMOKE_DIR}/velocity.pipe"

(
  cd "${SMOKE_DIR}/auth"
  "${SMOKE_JAVA}" -Xms32m -Xmx128m -jar NanoLimbo.jar \
    <"${SMOKE_DIR}/auth.pipe" >"${SMOKE_DIR}/auth.log" 2>&1
) &
AUTH_PID=$!
(
  cd "${SMOKE_DIR}/backend"
  "${SMOKE_JAVA}" -Xms32m -Xmx128m -jar NanoLimbo.jar \
    <"${SMOKE_DIR}/backend.pipe" >"${SMOKE_DIR}/backend.log" 2>&1
) &
BACKEND_PID=$!

wait_for_log() {
  local pid="$1"
  local log="$2"
  local pattern="$3"
  local label="$4"
  for _ in {1..120}; do
    if grep -Fq "${pattern}" "${log}" 2>/dev/null; then
      return
    fi
    if ! kill -0 "${pid}" 2>/dev/null; then
      break
    fi
    sleep 0.25
  done
  echo "${label} did not become ready" >&2
  tail -120 "${log}" >&2 || true
  exit 1
}
wait_for_log "${AUTH_PID}" "${SMOKE_DIR}/auth.log" "Server started on" "NanoLimbo auth server"
wait_for_log "${BACKEND_PID}" "${SMOKE_DIR}/backend.log" "Server started on" "NanoLimbo backend"

(
  cd "${SMOKE_DIR}/velocity"
  "${SMOKE_JAVA}" -Xms128m -Xmx512m -jar velocity.jar \
    <"${SMOKE_DIR}/velocity.pipe" >"${SMOKE_DIR}/velocity.log" 2>&1
) &
VELOCITY_PID=$!
wait_for_log "${VELOCITY_PID}" "${SMOKE_DIR}/velocity.log" \
  "Ready - player connections allowed" "Velocity external-mode proxy"

run_journey_phase() {
  local phase="$1"
  "${MAVEN[@]}" -q -f "${PROJECT_DIR}/pom.xml" \
    -Dtest=VelocityExternalJourneyIT \
    -Dveloauth.external.host=127.0.0.1 \
    -Dveloauth.external.port="${PROXY_PORT}" \
    -Dveloauth.external.username="${JOURNEY_USERNAME}" \
    -Dveloauth.external.password="${JOURNEY_PASSWORD}" \
    -Dveloauth.external.auth-marker="${AUTH_MARKER}" \
    -Dveloauth.external.backend-marker="${BACKEND_MARKER}" \
    -Dveloauth.external.phase="${phase}" test
}
run_journey_phase register
run_journey_phase login
run_journey_phase reconnect

[[ "$(sha256_file "${PLUGIN_JAR}")" == "${CANDIDATE_SHA256}" ]] || {
  echo "External journey mutated the supplied VeloAuth candidate" >&2
  exit 1
}

printf 'shutdown\n' >&5
wait "${VELOCITY_PID}"
VELOCITY_PID=""
printf 'stop\n' >&3
wait "${AUTH_PID}"
AUTH_PID=""
printf 'stop\n' >&4
wait "${BACKEND_PID}"
BACKEND_PID=""

grep -Fq "VeloAuth shutdown completed successfully" "${SMOKE_DIR}/velocity.log" || {
  echo "Velocity did not observe a clean VeloAuth shutdown" >&2
  tail -120 "${SMOKE_DIR}/velocity.log" >&2
  exit 1
}
PASSWORD_LEAK=false
while IFS= read -r -d '' candidate; do
  if grep -Fq -- "${JOURNEY_PASSWORD}" "${candidate}"; then
    PASSWORD_LEAK=true
    break
  fi
done < <(find "${SMOKE_DIR}" -type f -print0)
if [[ "${PASSWORD_LEAK}" == true ]]; then
  echo "External journey password leaked into a generated file or log" >&2
  exit 1
fi

EVIDENCE_DIR="$(mktemp -d "${PROJECT_DIR}/target/external-smoke-evidence.XXXXXX")"
cp "${SMOKE_DIR}/velocity.log" "${EVIDENCE_DIR}/velocity.log"
cp "${SMOKE_DIR}/auth.log" "${EVIDENCE_DIR}/nanolimbo-auth.log"
cp "${SMOKE_DIR}/backend.log" "${EVIDENCE_DIR}/nanolimbo-backend.log"
cat >"${EVIDENCE_DIR}/journey.txt" <<EOF
VeloAuth external-mode journey: PASS
candidate_sha256=${CANDIDATE_SHA256}
velocity_sha256=${VELOCITY_SHA256}
nanolimbo_version=1.13.0
nanolimbo_sha256=${NANOLIMBO_SHA256}
flow=auth -> register -> backend -> logout -> auth -> login -> backend -> disconnect -> auth -> login -> backend
EOF

echo "External VeloAuth journey passed; evidence: ${EVIDENCE_DIR}"
