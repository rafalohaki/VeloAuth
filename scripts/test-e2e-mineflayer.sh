#!/usr/bin/env bash
# End-to-end Mineflayer bot tests for VeloAuth against a real Velocity proxy.
#
# Topologies:
#   embedded   - VeloAuth embedded limbo auth server (no external processes)
#   picolimbo  - external PicoLimbo limbo referenced from velocity.toml
#   all        - both (default)
#
# Offline-mode only: premium Mojang session auth cannot be simulated by a bot.
# The first bot connects the moment the proxy port opens - before VeloAuth
# finishes async init - which reproduces the issue #48 "first player after
# proxy startup" scenario through the EarlyLoginBlocker queue.
#
# Requirements: java 21+, node >= 22, npm, curl, network access (first run
# downloads Velocity, PicoLimbo and the embedded ViaVersion runtime).
set -euo pipefail

TOPOLOGY="${1:-all}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
E2E_DIR="${ROOT}/e2e"
CACHE_DIR="${E2E_DIR}/.cache"
RUN_ROOT="${ROOT}/target/e2e"

VELOCITY_URL="https://fill-data.papermc.io/v1/objects/b4e3164df5377346854dc6cb9e6a78022b1946ff69e89676313f5f6f1c6f0fb3/velocity-3.5.1-615.jar"
VELOCITY_SHA256="b4e3164df5377346854dc6cb9e6a78022b1946ff69e89676313f5f6f1c6f0fb3"
PICO_URL="https://github.com/Quozul/PicoLimbo/releases/download/v1.13.2%2Bmc26.2/pico_limbo_linux-x86_64-gnu.tar.gz"
PICO_SHA256="75f34b7d379c5b94cb425c395a9c366b34a2779b9acb7b924db8a6c9f846f2de"

PIDS=()
cleanup() {
  for pid in "${PIDS[@]:-}"; do
    kill "${pid}" >/dev/null 2>&1 || true
  done
  wait >/dev/null 2>&1 || true
}
trap cleanup EXIT

fail() {
  echo "E2E: $*" >&2
  exit 1
}

fetch() {
  local url=$1 sha=$2 out=$3
  if [[ ! -f "${out}" ]] || ! echo "${sha}  ${out}" | sha256sum -c --quiet - 2>/dev/null; then
    echo "E2E: downloading $(basename "${out}")"
    curl -fsSL -o "${out}" "${url}"
    echo "${sha}  ${out}" | sha256sum -c --quiet - || fail "checksum mismatch for ${out}"
  fi
}

free_port() {
  python3 - <<'PY'
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
}

find_plugin_jar() {
  local jar
  if [[ -n "${VELOAUTH_E2E_JAR:-}" ]]; then
    [[ -f "${VELOAUTH_E2E_JAR}" ]] || fail "VELOAUTH_E2E_JAR not found: ${VELOAUTH_E2E_JAR}"
    echo "${VELOAUTH_E2E_JAR}"
    return
  fi
  jar=$(ls "${ROOT}"/target/veloauth-*.jar 2>/dev/null | grep -v original | head -1 || true)
  if [[ -z "${jar}" ]]; then
    echo "E2E: building plugin jar" >&2
    (cd "${ROOT}" && ./mvnw -q clean package -DskipTests)
    jar=$(ls "${ROOT}"/target/veloauth-*.jar | grep -v original | head -1)
  fi
  echo "${jar}"
}

write_velocity_toml() {
  local dir=$1 proxy_port=$2 limbo_port=$3
  {
    echo 'config-version = "2.7"'
    echo "bind = \"127.0.0.1:${proxy_port}\""
    echo 'motd = "VeloAuth e2e"'
    echo 'online-mode = false'
    echo 'force-key-authentication = false'
    echo 'player-info-forwarding-mode = "NONE"'
    echo 'forwarding-secret-file = "forwarding.secret"'
    echo '[servers]'
    if [[ -n "${limbo_port}" ]]; then
      echo "limbo = \"127.0.0.1:${limbo_port}\""
    fi
    # Dead dummy backend: pre-auth players are redirected to the auth server
    # before Velocity ever dials it, and the post-auth transfer failure is
    # outside these scenarios' assertions.
    echo 'backend = "127.0.0.1:9"'
    echo 'try = ["backend"]'
    echo '[forced-hosts]'
  } > "${dir}/velocity.toml"
  : > "${dir}/forwarding.secret"
}

write_veloauth_config() {
  local dir=$1 mode=$2
  mkdir -p "${dir}/plugins/veloauth"
  {
    echo 'database:'
    echo '  storage-type: H2'
    echo 'premium:'
    echo '  check-enabled: false'
    echo 'auth-server:'
    echo "  mode: ${mode}"
    echo '  server-name: limbo'
    echo '  timeout-seconds: 120'
  } > "${dir}/plugins/veloauth/config.yml"
}

wait_for_port() {
  local port=$1 deadline=$((SECONDS + 120))
  until python3 -c "import socket,sys; s=socket.socket(); s.settimeout(0.5); sys.exit(0 if s.connect_ex(('127.0.0.1', ${port})) == 0 else 1)" 2>/dev/null; do
    if (( SECONDS >= deadline )); then
      return 1
    fi
    sleep 0.5
  done
}

run_topology() {
  local topology=$1
  local dir="${RUN_ROOT}/${topology}"
  rm -rf "${dir}"
  mkdir -p "${dir}"

  local proxy_port limbo_port=""
  proxy_port=$(free_port)

  if [[ "${topology}" == "picolimbo" ]]; then
    limbo_port=$(free_port)
    tar -xzf "${CACHE_DIR}/pico_limbo.tar.gz" -C "${dir}"
    printf 'bind = "127.0.0.1:%s"\n\n[forwarding]\nmethod = "NONE"\n' "${limbo_port}" \
      > "${dir}/server.toml"
    (cd "${dir}" && ./pico_limbo --skip-banner > pico.log 2>&1) &
    PIDS+=($!)
    wait_for_port "${limbo_port}" || { cat "${dir}/pico.log" >&2; fail "PicoLimbo did not start"; }
    write_veloauth_config "${dir}" external
  else
    write_veloauth_config "${dir}" embedded
  fi

  write_velocity_toml "${dir}" "${proxy_port}" "${limbo_port}"
  cp "${PLUGIN_JAR}" "${dir}/plugins/"

  (cd "${dir}" && java -Xmx512M -jar "${CACHE_DIR}/velocity.jar" > velocity.log 2>&1) &
  PIDS+=($!)

  # Connect the very first bot as soon as the port accepts TCP - VeloAuth may
  # still be initializing, which is exactly the issue #48 startup-queue window.
  wait_for_port "${proxy_port}" || { tail -50 "${dir}/velocity.log" >&2; fail "Velocity did not start (${topology})"; }

  local bots_failed=0
  node "${E2E_DIR}/bot.js" 127.0.0.1 "${proxy_port}" "E2eFirst${RANDOM}x" prompt-register \
    || bots_failed=1
  if [[ ${bots_failed} -eq 0 ]]; then
    local nick="E2eCycle${RANDOM}x"
    node "${E2E_DIR}/bot.js" 127.0.0.1 "${proxy_port}" "${nick}" prompt-register \
      && node "${E2E_DIR}/bot.js" 127.0.0.1 "${proxy_port}" "${nick}" login \
      || bots_failed=1
  fi

  if [[ ${bots_failed} -ne 0 ]]; then
    echo "--- velocity.log tail (${topology}) ---" >&2
    tail -80 "${dir}/velocity.log" >&2
    fail "topology '${topology}' failed"
  fi
  echo "E2E: topology '${topology}' passed"
  cleanup
  PIDS=()
}

case "${TOPOLOGY}" in
  embedded|picolimbo|all) ;;
  *) fail "usage: $0 [embedded|picolimbo|all]" ;;
esac

command -v node >/dev/null || fail "node >= 22 is required"
command -v java >/dev/null || fail "java 21+ is required"

mkdir -p "${CACHE_DIR}" "${RUN_ROOT}"
fetch "${VELOCITY_URL}" "${VELOCITY_SHA256}" "${CACHE_DIR}/velocity.jar"
if [[ "${TOPOLOGY}" != "embedded" ]]; then
  fetch "${PICO_URL}" "${PICO_SHA256}" "${CACHE_DIR}/pico_limbo.tar.gz"
fi
if [[ ! -d "${E2E_DIR}/node_modules/mineflayer" ]]; then
  echo "E2E: installing mineflayer"
  (cd "${E2E_DIR}" && npm install --no-audit --no-fund --loglevel=error)
fi

PLUGIN_JAR=$(find_plugin_jar)
echo "E2E: using plugin jar $(basename "${PLUGIN_JAR}")"

if [[ "${TOPOLOGY}" == "all" ]]; then
  run_topology embedded
  run_topology picolimbo
else
  run_topology "${TOPOLOGY}"
fi
echo "E2E: all Mineflayer scenarios passed"
