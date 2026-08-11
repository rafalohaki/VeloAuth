#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
VELOCITY_URL="https://fill-data.papermc.io/v1/objects/0c3d16b70ed757638b696a9a87d670b4301f23a6fef30c3acbbd9b0e0d7b29bb/velocity-3.5.0-SNAPSHOT-609.jar"
VELOCITY_SHA256="0c3d16b70ed757638b696a9a87d670b4301f23a6fef30c3acbbd9b0e0d7b29bb"
TARGETS="${VELOAUTH_CAPACITY_TARGETS:-1000,5000,10000}"
CONNECT_CONCURRENCY="${VELOAUTH_CAPACITY_CONNECT_CONCURRENCY:-256}"
STATUS_SAMPLES="${VELOAUTH_CAPACITY_STATUS_SAMPLES:-60}"
MAX_STATUS_P95_MS="${VELOAUTH_CAPACITY_MAX_STATUS_P95_MS:-250}"
MAX_STATUS_MAX_MS="${VELOAUTH_CAPACITY_MAX_STATUS_MAX_MS:-1500}"
MAX_HEAP_USAGE_PERCENT="${VELOAUTH_CAPACITY_MAX_HEAP_USAGE_PERCENT:-90}"
MAX_DARWIN_SELECTOR_WARNINGS="${VELOAUTH_CAPACITY_MAX_DARWIN_SELECTOR_WARNINGS:-2}"
PROXY_XMS="${VELOAUTH_CAPACITY_PROXY_XMS:-2g}"
PROXY_XMX="${VELOAUTH_CAPACITY_PROXY_XMX:-10g}"
CLIENT_XMS="${VELOAUTH_CAPACITY_CLIENT_XMS:-1g}"
CLIENT_XMX="${VELOAUTH_CAPACITY_CLIENT_XMX:-6g}"
if [[ "$(uname -s)" == Darwin ]]; then
  DEFAULT_PROXY_HOST="::1"
else
  DEFAULT_PROXY_HOST="127.0.0.1"
fi
PROXY_HOST="${VELOAUTH_CAPACITY_PROXY_HOST:-${DEFAULT_PROXY_HOST}}"
PLUGIN_JAR_OVERRIDE="${VELOAUTH_PLUGIN_JAR:-}"
JAVA_COMMAND="${VELOAUTH_CAPACITY_JAVA:-${JAVA_HOME:-}/bin/java}"
VELOCITY_PID=""
LOAD_PID=""
CONSOLE_OPEN=false

if [[ ! "${TARGETS}" =~ ^[1-9][0-9]*(,[1-9][0-9]*)*$ ]]; then
  echo "VELOAUTH_CAPACITY_TARGETS must be a comma-separated positive integer list" >&2
  exit 1
fi
if [[ ! "${CONNECT_CONCURRENCY}" =~ ^[1-9][0-9]*$ \
    || ! "${STATUS_SAMPLES}" =~ ^[1-9][0-9]*$ \
    || ! "${MAX_STATUS_P95_MS}" =~ ^[1-9][0-9]*$ \
    || ! "${MAX_STATUS_MAX_MS}" =~ ^[1-9][0-9]*$ \
    || ! "${MAX_HEAP_USAGE_PERCENT}" =~ ^[1-9][0-9]*$ \
    || ! "${MAX_DARWIN_SELECTOR_WARNINGS}" =~ ^[0-9]+$ ]]; then
  echo "Capacity concurrency, sample count and latency budgets must be positive integers" >&2
  exit 1
fi
if (( MAX_HEAP_USAGE_PERCENT > 100 )); then
  echo "VELOAUTH_CAPACITY_MAX_HEAP_USAGE_PERCENT cannot exceed 100" >&2
  exit 1
fi
case "${PROXY_HOST}" in
  ::1|127.0.0.1) ;;
  *)
    echo "VELOAUTH_CAPACITY_PROXY_HOST must be the IPv4 or IPv6 loopback literal" >&2
    exit 1
    ;;
esac

if [[ "${JAVA_COMMAND}" != /* || ! -x "${JAVA_COMMAND}" ]]; then
  echo "VELOAUTH_CAPACITY_JAVA or JAVA_HOME must identify an absolute Java executable" >&2
  exit 1
fi
JAVA_BIN_DIR="$(cd -- "$(dirname -- "${JAVA_COMMAND}")" && pwd)"
JCMD="${JAVA_BIN_DIR}/jcmd"
JSTAT="${JAVA_BIN_DIR}/jstat"
JFR="${JAVA_BIN_DIR}/jfr"
for executable in "${JCMD}" "${JFR}"; do
  [[ -x "${executable}" ]] || {
    echo "The capacity JDK must include $(basename -- "${executable}")" >&2
    exit 1
  }
done
for command in curl lsof python3 ps awk grep; do
  command -v "${command}" >/dev/null 2>&1 || {
    echo "${command} is required for the real Velocity capacity profile" >&2
    exit 1
  }
done
if [[ "$(uname -s)" == Darwin ]] && ! command -v netstat >/dev/null 2>&1; then
  echo "netstat is required to count large macOS socket tables accurately" >&2
  exit 1
fi

JAVA_MAJOR="$("${JAVA_COMMAND}" -XshowSettings:properties -version 2>&1 \
  | awk -F'= ' '/^[[:space:]]*java.specification.version = / { print $2; exit }')"
if [[ "${JAVA_MAJOR}" != 21 ]]; then
  echo "The VeloAuth capacity profile requires Java 21; found ${JAVA_MAJOR:-unknown}" >&2
  exit 1
fi

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

if [[ -n "${PLUGIN_JAR_OVERRIDE}" ]]; then
  if [[ "${PLUGIN_JAR_OVERRIDE}" != /* || ! -f "${PLUGIN_JAR_OVERRIDE}" \
      || -L "${PLUGIN_JAR_OVERRIDE}" ]]; then
    echo "VELOAUTH_PLUGIN_JAR must be an absolute regular non-symlink file" >&2
    exit 1
  fi
  PLUGIN_JAR="${PLUGIN_JAR_OVERRIDE}"
else
  FINAL_NAME="$(evaluate_maven_expression project.build.finalName)"
  PLUGIN_JAR="${PROJECT_DIR}/target/${FINAL_NAME}.jar"
fi
if [[ ! -f "${PLUGIN_JAR}" ]]; then
  if [[ -n "${PLUGIN_JAR_OVERRIDE}" ]]; then
    echo "Requested VeloAuth plugin JAR does not exist" >&2
    exit 1
  fi
  "${MAVEN[@]}" -f "${PROJECT_DIR}/pom.xml" -DskipTests package
fi
PLUGIN_SHA256="$(sha256_file "${PLUGIN_JAR}")"

mkdir -p "${PROJECT_DIR}/target"
if [[ -n "${VELOAUTH_CAPACITY_EVIDENCE_DIR:-}" ]]; then
  EVIDENCE_DIR="${VELOAUTH_CAPACITY_EVIDENCE_DIR}"
  if [[ "${EVIDENCE_DIR}" != /* || -e "${EVIDENCE_DIR}" \
      || ! -d "$(dirname -- "${EVIDENCE_DIR}")" ]]; then
    echo "VELOAUTH_CAPACITY_EVIDENCE_DIR must be a fresh absolute path with an existing parent" >&2
    exit 1
  fi
  mkdir "${EVIDENCE_DIR}"
else
  EVIDENCE_DIR="$(mktemp -d "${PROJECT_DIR}/target/velocity-capacity-evidence.XXXXXX")"
fi
WORK_DIR="${EVIDENCE_DIR}/work"
CONTROL_DIR="${EVIDENCE_DIR}/control"
mkdir -p "${WORK_DIR}/plugins/veloauth" "${WORK_DIR}/plugins/bStats" "${CONTROL_DIR}"

cleanup_process() {
  local pid="$1"
  local signal="${2:-TERM}"
  if [[ -n "${pid}" ]] && kill -0 "${pid}" 2>/dev/null; then
    kill -s "${signal}" "${pid}" 2>/dev/null || true
    for _ in {1..40}; do
      if ! kill -0 "${pid}" 2>/dev/null; then
        return
      fi
      sleep 0.25
    done
    kill -KILL "${pid}" 2>/dev/null || true
  fi
}

cleanup() {
  cleanup_process "${LOAD_PID}"
  if [[ -n "${VELOCITY_PID}" ]] && kill -0 "${VELOCITY_PID}" 2>/dev/null; then
    if [[ "${CONSOLE_OPEN}" == true ]]; then
      printf 'shutdown\n' >&3 2>/dev/null || true
    fi
    for _ in {1..40}; do
      if ! kill -0 "${VELOCITY_PID}" 2>/dev/null; then
        break
      fi
      sleep 0.25
    done
    cleanup_process "${VELOCITY_PID}"
  fi
  if [[ "${CONSOLE_OPEN}" == true ]]; then
    exec 3>&- || true
  fi
  echo "Velocity capacity evidence preserved at: ${EVIDENCE_DIR}" >&2
}
trap cleanup EXIT

MAX_TARGET="$(python3 - "${TARGETS}" <<'PY'
import sys
values = [int(value) for value in sys.argv[1].split(',')]
if any(value < 1 or value > 10_000 for value in values):
    raise SystemExit("capacity targets must be in range 1..10000")
if values != sorted(set(values)):
    raise SystemExit("capacity targets must be strictly ascending and unique")
print(values[-1])
PY
)"
if (( CONNECT_CONCURRENCY > MAX_TARGET )); then
  echo "VELOAUTH_CAPACITY_CONNECT_CONCURRENCY cannot exceed the largest target" >&2
  exit 1
fi

OPEN_FILE_LIMIT="$(ulimit -n)"
REQUIRED_PROCESS_FILES=$((MAX_TARGET * 3 + 1024))
if [[ "${OPEN_FILE_LIMIT}" != unlimited ]] && (( OPEN_FILE_LIMIT < REQUIRED_PROCESS_FILES )); then
  echo "Open-file limit ${OPEN_FILE_LIMIT} is below required proxy budget ${REQUIRED_PROCESS_FILES}" >&2
  exit 1
fi
if [[ "$(uname -s)" == Darwin ]]; then
  EPHEMERAL_FIRST="$(sysctl -n net.inet.ip.portrange.hifirst)"
  EPHEMERAL_LAST="$(sysctl -n net.inet.ip.portrange.hilast)"
  EPHEMERAL_COUNT=$((EPHEMERAL_LAST - EPHEMERAL_FIRST + 1))
  REQUIRED_EPHEMERAL_PORTS=$((MAX_TARGET + 1024))
  if [[ "${PROXY_HOST}" == 127.0.0.1 ]]; then
    REQUIRED_EPHEMERAL_PORTS=$((MAX_TARGET * 2 + 1024))
  fi
  if (( EPHEMERAL_COUNT < REQUIRED_EPHEMERAL_PORTS )); then
    echo "macOS ephemeral port range ${EPHEMERAL_COUNT} is below required budget ${REQUIRED_EPHEMERAL_PORTS}" >&2
    exit 1
  fi
fi

HOST_MEMORY_BYTES="$(python3 <<'PY'
import pathlib
import subprocess
if pathlib.Path('/proc/meminfo').is_file():
    for line in pathlib.Path('/proc/meminfo').read_text().splitlines():
        if line.startswith('MemTotal:'):
            print(int(line.split()[1]) * 1024)
            break
else:
    print(subprocess.check_output(['sysctl', '-n', 'hw.memsize'], text=True).strip())
PY
)"
if (( MAX_TARGET >= 10000 && HOST_MEMORY_BYTES < 20 * 1024 * 1024 * 1024 )); then
  echo "The default 10k profile requires at least 20 GiB host memory" >&2
  exit 1
fi

{
  echo "targets=${TARGETS}"
  echo "connect_concurrency=${CONNECT_CONCURRENCY}"
  echo "ulimit_n=${OPEN_FILE_LIMIT}"
  echo "required_process_files=${REQUIRED_PROCESS_FILES}"
  echo "host_memory_bytes=${HOST_MEMORY_BYTES}"
  echo "proxy_heap=${PROXY_XMS}/${PROXY_XMX}"
  echo "client_heap=${CLIENT_XMS}/${CLIENT_XMX}"
  echo "max_heap_usage_percent=${MAX_HEAP_USAGE_PERCENT}"
  echo "max_darwin_selector_warnings=${MAX_DARWIN_SELECTOR_WARNINGS}"
  echo "proxy_host=${PROXY_HOST}"
  echo "java_command=${JAVA_COMMAND}"
  "${JAVA_COMMAND}" -version 2>&1
  uname -a
  sysctl kern.maxfiles kern.maxfilesperproc net.inet.ip.portrange.hifirst \
    net.inet.ip.portrange.hilast 2>/dev/null || true
  if [[ -r /proc/sys/net/ipv4/ip_local_port_range ]]; then
    printf 'ip_local_port_range='
    tr '\t' '-' </proc/sys/net/ipv4/ip_local_port_range
  fi
} >"${EVIDENCE_DIR}/host-limits.txt"
printf '%s  %s\n' "${PLUGIN_SHA256}" "$(basename -- "${PLUGIN_JAR}")" \
  >"${EVIDENCE_DIR}/candidate.sha256"

curl --proto '=https' --proto-redir '=https' --tlsv1.2 \
  --fail --silent --show-error --location --max-time 60 --max-filesize 100000000 \
  --output "${WORK_DIR}/velocity.jar" "${VELOCITY_URL}"
if [[ "$(sha256_file "${WORK_DIR}/velocity.jar")" != "${VELOCITY_SHA256}" ]]; then
  echo "Pinned Velocity capacity binary checksum mismatch" >&2
  exit 1
fi
cp "${PLUGIN_JAR}" "${WORK_DIR}/plugins/veloauth.jar"

PROXY_PORT="$(python3 - "${PROXY_HOST}" <<'PY'
import socket
import sys
host = sys.argv[1]
family = socket.AF_INET6 if host == '::1' else socket.AF_INET
with socket.socket(family) as sock:
    sock.bind((host, 0))
    print(sock.getsockname()[1])
PY
)"
case "${PROXY_HOST}" in
  ::1) PROXY_BIND_ADDRESS="[::1]:${PROXY_PORT}" ;;
  127.0.0.1) PROXY_BIND_ADDRESS="127.0.0.1:${PROXY_PORT}" ;;
esac

cat >"${WORK_DIR}/velocity.toml" <<TOML
config-version = "2.9"
bind = "${PROXY_BIND_ADDRESS}"
online-mode = false
player-info-forwarding-mode = "none"
forwarding-secret-file = "forwarding.secret"
show-max-players = ${MAX_TARGET}

[servers]
lobby = "127.0.0.1:30066"
try = ["lobby"]

[forced-hosts]

[advanced]
login-ratelimit = 0
TOML
printf '%s\n' 'capacity-profile-loopback-only-unused-secret' >"${WORK_DIR}/forwarding.secret"
cat >"${WORK_DIR}/plugins/veloauth/config.yml" <<YAML
language: en
database:
  storage-type: H2
premium:
  check-enabled: false
auth-server:
  mode: embedded
  timeout-seconds: 900
  embedded:
    reviewed-runtime-updates: false
    port: 0
    max-connections: ${MAX_TARGET}
    handshake-timeout-seconds: 30
    login-timeout-seconds: 120
connection:
  auto-transfer-delay-ms: 1500
report:
  enabled: false
YAML
cat >"${WORK_DIR}/plugins/bStats/config.txt" <<'YAML'
enabled: false
YAML

mkfifo "${WORK_DIR}/console.pipe"
exec 3<>"${WORK_DIR}/console.pipe"
CONSOLE_OPEN=true
(
  cd "${WORK_DIR}"
  exec "${JAVA_COMMAND}" \
    "-Xms${PROXY_XMS}" "-Xmx${PROXY_XMX}" \
    -XX:NativeMemoryTracking=summary \
    "-XX:StartFlightRecording=filename=${EVIDENCE_DIR}/velocity.jfr,settings=profile,dumponexit=true,maxsize=512m" \
    -jar velocity.jar --port "${PROXY_PORT}" \
    <"${WORK_DIR}/console.pipe" >"${EVIDENCE_DIR}/velocity.log" 2>&1
) &
VELOCITY_PID=$!

READY=false
for _ in {1..360}; do
  if grep -Fq "Ready - player connections allowed" "${EVIDENCE_DIR}/velocity.log" 2>/dev/null; then
    READY=true
    break
  fi
  if ! kill -0 "${VELOCITY_PID}" 2>/dev/null; then
    break
  fi
  sleep 0.25
done
if [[ "${READY}" != true ]]; then
  echo "Velocity capacity proxy did not become ready" >&2
  tail -160 "${EVIDENCE_DIR}/velocity.log" >&2 || true
  exit 1
fi

count_established_tcp() {
  local pid="$1"
  if [[ "$(uname -s)" == Darwin ]]; then
    # Apple's bundled lsof 4.91 under-enumerates large Java descriptor tables. netstat's
    # kernel socket table retains the exact owning PID and remains accurate above 10k FDs.
    netstat -anv -p tcp 2>/dev/null \
      | awk -v owner=":${pid}" '$6 == "ESTABLISHED" && index($0, owner) { count++ }
          END { print count + 0 }'
  else
    lsof -nP -a -p "${pid}" -iTCP -sTCP:ESTABLISHED -Ff 2>/dev/null \
      | awk '/^f[0-9]+$/ { count++ } END { print count + 0 }'
  fi
}

BASELINE_PROXY_TCP="$(count_established_tcp "${VELOCITY_PID}")"
echo "baseline_proxy_tcp=${BASELINE_PROXY_TCP}" >>"${EVIDENCE_DIR}/host-limits.txt"

CLASSPATH_FILE="${CONTROL_DIR}/test-classpath.txt"
JAVA_HOME="$(cd -- "${JAVA_BIN_DIR}/.." && pwd)" PATH="${JAVA_BIN_DIR}:${PATH}" \
  "${MAVEN[@]}" -B -ntp -f "${PROJECT_DIR}/pom.xml" test-compile \
  dependency:build-classpath -Dmdep.includeScope=test \
  "-Dmdep.outputFile=${CLASSPATH_FILE}" -Dmdep.pathSeparator=: \
  >"${EVIDENCE_DIR}/test-compile.log" 2>&1
TEST_CLASSPATH="${PROJECT_DIR}/target/test-classes:${PROJECT_DIR}/target/classes:$(<"${CLASSPATH_FILE}")"

"${JAVA_COMMAND}" "-Xms${CLIENT_XMS}" "-Xmx${CLIENT_XMX}" \
  -Dio.netty.eventLoopThreads=10 \
  "-Dveloauth.capacity.host=${PROXY_HOST}" \
  "-Dveloauth.capacity.port=${PROXY_PORT}" \
  "-Dveloauth.capacity.targets=${TARGETS}" \
  "-Dveloauth.capacity.connect-concurrency=${CONNECT_CONCURRENCY}" \
  -Dveloauth.capacity.batch-timeout-seconds=900 \
  -Dveloauth.capacity.control-timeout-seconds=600 \
  "-Dveloauth.capacity.control-dir=${CONTROL_DIR}" \
  -cp "${TEST_CLASSPATH}" \
  net.rafalohaki.veloauth.authserver.VelocityEmbeddedCapacityProfile \
  >"${EVIDENCE_DIR}/load-generator.log" 2>&1 &
LOAD_PID=$!

measure_status_latency() {
  local target="$1"
  python3 - "${PROXY_HOST}" "${PROXY_PORT}" "${STATUS_SAMPLES}" "${target}" <<'PY'
import json
import socket
import statistics
import struct
import sys
import time

host_name = sys.argv[1]
port = int(sys.argv[2])
samples = int(sys.argv[3])
target = int(sys.argv[4])

def varint(value):
    encoded = bytearray()
    while True:
        part = value & 0x7f
        value >>= 7
        if value:
            part |= 0x80
        encoded.append(part)
        if not value:
            return bytes(encoded)

def read_varint(sock):
    result = 0
    for position in range(5):
        byte = sock.recv(1)
        if not byte:
            raise EOFError('status response ended before VarInt')
        value = byte[0]
        result |= (value & 0x7f) << (7 * position)
        if value & 0x80 == 0:
            return result
    raise ValueError('status VarInt is too long')

latencies = []
for _ in range(samples):
    started = time.perf_counter_ns()
    with socket.create_connection((host_name, port), timeout=3) as sock:
        sock.settimeout(3)
        host = host_name.encode('ascii')
        handshake = b'\x00' + varint(47) + varint(len(host)) + host + struct.pack('>H', port) + b'\x01'
        sock.sendall(varint(len(handshake)) + handshake + b'\x01\x00')
        frame_length = read_varint(sock)
        frame = bytearray()
        while len(frame) < frame_length:
            chunk = sock.recv(frame_length - len(frame))
            if not chunk:
                raise EOFError('short status response')
            frame.extend(chunk)
        if not frame or frame[0] != 0:
            raise ValueError('unexpected status response packet')
    latencies.append((time.perf_counter_ns() - started) / 1_000_000)

latencies.sort()
percentile_index = max(0, min(len(latencies) - 1, int((len(latencies) - 1) * 0.95)))
print(f'target={target}')
print(f'samples={len(latencies)}')
print(f'p50_ms={statistics.median(latencies):.3f}')
print(f'p95_ms={latencies[percentile_index]:.3f}')
print(f'max_ms={max(latencies):.3f}')
PY
}

sample_plateau() {
  local target="$1"
  local summary="${EVIDENCE_DIR}/plateau-${target}.txt"
  local latency="${EVIDENCE_DIR}/plateau-${target}-latency.txt"
  local heap_info="${EVIDENCE_DIR}/plateau-${target}-heap-info.txt"
  local proxy_tcp load_tcp proxy_rss proxy_vsz load_rss load_vsz delta
  local heap_total_kb heap_used_kb heap_usage_percent

  measure_status_latency "${target}" >"${latency}"
  proxy_tcp="$(count_established_tcp "${VELOCITY_PID}")"
  load_tcp="$(count_established_tcp "${LOAD_PID}")"
  read -r proxy_rss proxy_vsz < <(ps -o rss=,vsz= -p "${VELOCITY_PID}" | awk 'NF { print $1, $2 }')
  read -r load_rss load_vsz < <(ps -o rss=,vsz= -p "${LOAD_PID}" | awk 'NF { print $1, $2 }')
  delta=$((proxy_tcp - BASELINE_PROXY_TCP))

  "${JCMD}" "${VELOCITY_PID}" GC.heap_info >"${heap_info}"
  read -r heap_total_kb heap_used_kb < <(
    awk '/ heap +total [0-9]+K, used [0-9]+K/ {
      gsub(/[^0-9]/, "", $4)
      gsub(/[^0-9]/, "", $6)
      print $4, $6
      exit
    }' "${heap_info}"
  )
  if [[ ! "${heap_total_kb}" =~ ^[1-9][0-9]*$ \
      || ! "${heap_used_kb}" =~ ^[0-9]+$ ]]; then
    echo "Unable to parse the Velocity heap evidence for plateau ${target}" >&2
    exit 1
  fi
  heap_usage_percent="$(awk -v used="${heap_used_kb}" -v total="${heap_total_kb}" \
    'BEGIN { printf "%.2f", used * 100 / total }')"

  "${JCMD}" "${VELOCITY_PID}" VM.native_memory summary scale=KB \
    >"${EVIDENCE_DIR}/plateau-${target}-native-memory.txt"
  "${JCMD}" "${VELOCITY_PID}" GC.class_histogram \
    >"${EVIDENCE_DIR}/plateau-${target}-class-histogram.txt"
  if [[ -x "${JSTAT}" ]]; then
    "${JSTAT}" -gcutil "${VELOCITY_PID}" 1000 5 \
      >"${EVIDENCE_DIR}/plateau-${target}-gcutil.txt"
  fi
  vm_stat >"${EVIDENCE_DIR}/plateau-${target}-vm-stat.txt" 2>/dev/null || true

  {
    cat "${CONTROL_DIR}/plateau-${target}.ready"
    echo "proxy_pid=${VELOCITY_PID}"
    echo "load_generator_pid=${LOAD_PID}"
    echo "proxy_rss_kb=${proxy_rss}"
    echo "proxy_vsz_kb=${proxy_vsz}"
    echo "load_generator_rss_kb=${load_rss}"
    echo "load_generator_vsz_kb=${load_vsz}"
    echo "proxy_tcp_established=${proxy_tcp}"
    echo "proxy_tcp_baseline=${BASELINE_PROXY_TCP}"
    echo "proxy_tcp_delta=${delta}"
    echo "load_generator_tcp_established=${load_tcp}"
    echo "heap_total_kb=${heap_total_kb}"
    echo "heap_used_kb=${heap_used_kb}"
    echo "heap_usage_percent=${heap_usage_percent}"
    awk -F= '/^(p50_ms|p95_ms|max_ms)=/ { print }' "${latency}"
  } >"${summary}"

  python3 - "${target}" "${delta}" "${load_tcp}" \
    "$(awk -F= '/^p95_ms=/ { print $2 }' "${latency}")" \
    "$(awk -F= '/^max_ms=/ { print $2 }' "${latency}")" \
    "${MAX_STATUS_P95_MS}" "${MAX_STATUS_MAX_MS}" \
    "${heap_used_kb}" "${heap_total_kb}" "${MAX_HEAP_USAGE_PERCENT}" <<'PY'
import sys
target, proxy_delta, load_fds = map(int, sys.argv[1:4])
p95, maximum, p95_budget, max_budget = map(float, sys.argv[4:8])
heap_used, heap_total, heap_budget = map(float, sys.argv[8:11])
if not 2.85 * target <= proxy_delta <= 3.15 * target:
    raise SystemExit(f'proxy descriptor ratio outside 2.85..3.15: {proxy_delta}/{target}')
if not 0.95 * target <= load_fds <= 1.05 * target:
    raise SystemExit(f'load-generator descriptor ratio outside 0.95..1.05: {load_fds}/{target}')
if p95 > p95_budget:
    raise SystemExit(f'status p95 {p95:.3f} ms exceeds budget {p95_budget:.3f} ms')
if maximum > max_budget:
    raise SystemExit(f'status max {maximum:.3f} ms exceeds budget {max_budget:.3f} ms')
heap_percent = heap_used * 100 / heap_total
if heap_percent > heap_budget:
    raise SystemExit(f'heap usage {heap_percent:.2f}% exceeds budget {heap_budget:.2f}%')
PY
}

IFS=',' read -r -a TARGET_ARRAY <<<"${TARGETS}"
for target in "${TARGET_ARRAY[@]}"; do
  READY_FILE="${CONTROL_DIR}/plateau-${target}.ready"
  PLATEAU_READY=false
  for _ in {1..7200}; do
    if [[ -f "${CONTROL_DIR}/profile.failed" ]]; then
      echo "Capacity load generator failed before plateau ${target}" >&2
      cat "${CONTROL_DIR}/profile.failed" >&2
      exit 1
    fi
    if [[ -f "${READY_FILE}" ]]; then
      PLATEAU_READY=true
      break
    fi
    if ! kill -0 "${LOAD_PID}" 2>/dev/null; then
      break
    fi
    if ! kill -0 "${VELOCITY_PID}" 2>/dev/null; then
      echo "Velocity exited during the capacity ramp" >&2
      tail -160 "${EVIDENCE_DIR}/velocity.log" >&2 || true
      exit 1
    fi
    sleep 0.25
  done
  if [[ "${PLATEAU_READY}" != true ]]; then
    echo "Capacity plateau ${target} did not become ready" >&2
    tail -160 "${EVIDENCE_DIR}/load-generator.log" >&2 || true
    exit 1
  fi
  sample_plateau "${target}"
  : >"${CONTROL_DIR}/plateau-${target}.continue"
done

wait "${LOAD_PID}"
LOAD_PID=""
if [[ ! -f "${CONTROL_DIR}/profile.complete" ]]; then
  echo "Capacity load generator exited without its completion marker" >&2
  tail -160 "${EVIDENCE_DIR}/load-generator.log" >&2 || true
  exit 1
fi

if [[ "$(sha256_file "${PLUGIN_JAR}")" != "${PLUGIN_SHA256}" ]]; then
  echo "Capacity profile mutated the supplied VeloAuth candidate" >&2
  exit 1
fi
if grep -Eq 'OutOfMemoryError|Embedded auth server at capacity|RejectedExecutionException' \
    "${EVIDENCE_DIR}/velocity.log"; then
  echo "Velocity capacity log contains a resource-safety failure" >&2
  tail -200 "${EVIDENCE_DIR}/velocity.log" >&2
  exit 1
fi

SELECTOR_WARNINGS="$(grep -Fc 'Unexpected exception in the selector loop.' \
  "${EVIDENCE_DIR}/velocity.log" || true)"
if [[ "$(uname -s)" == Darwin ]]; then
  if (( SELECTOR_WARNINGS > MAX_DARWIN_SELECTOR_WARNINGS )); then
    echo "Velocity emitted ${SELECTOR_WARNINGS} macOS selector-loop warnings; budget is ${MAX_DARWIN_SELECTOR_WARNINGS}" >&2
    exit 1
  fi
elif (( SELECTOR_WARNINGS > 0 )); then
  echo "Velocity emitted ${SELECTOR_WARNINGS} unexpected selector-loop warnings" >&2
  exit 1
fi

printf 'shutdown\n' >&3
wait "${VELOCITY_PID}"
VELOCITY_PID=""
if ! grep -Fq "VeloAuth shutdown completed successfully" "${EVIDENCE_DIR}/velocity.log"; then
  echo "Velocity capacity profile did not observe a clean VeloAuth shutdown" >&2
  tail -160 "${EVIDENCE_DIR}/velocity.log" >&2 || true
  exit 1
fi
if [[ ! -s "${EVIDENCE_DIR}/velocity.jfr" ]]; then
  echo "Velocity capacity profile produced no JFR recording" >&2
  exit 1
fi
"${JFR}" summary "${EVIDENCE_DIR}/velocity.jfr" >"${EVIDENCE_DIR}/jfr-summary.txt"

cat >"${EVIDENCE_DIR}/result.txt" <<EOF
VeloAuth real Velocity embedded capacity profile: PASS
targets=${TARGETS}
client_protocol=26.2
velocity_build=3.5.0-SNAPSHOT-609
velocity_sha256=${VELOCITY_SHA256}
candidate_sha256=${PLUGIN_SHA256}
proxy_descriptor_budget=approximately 3 established TCP descriptors per held player
status_p95_budget_ms=${MAX_STATUS_P95_MS}
status_max_budget_ms=${MAX_STATUS_MAX_MS}
max_heap_usage_percent=${MAX_HEAP_USAGE_PERCENT}
max_darwin_selector_warnings=${MAX_DARWIN_SELECTOR_WARNINGS}
darwin_selector_warnings=${SELECTOR_WARNINGS}
evidence=${EVIDENCE_DIR}
EOF

CONSOLE_OPEN=false
exec 3>&-
trap - EXIT
echo "Real Velocity embedded capacity profile passed: ${TARGETS} clients"
echo "Evidence preserved at: ${EVIDENCE_DIR}"
