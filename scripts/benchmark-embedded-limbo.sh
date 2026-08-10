#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
project_dir="$(cd -- "${script_dir}/.." && pwd)"
connections="${VELOAUTH_BENCHMARK_CONNECTIONS:-1000}"
concurrency="${VELOAUTH_BENCHMARK_CONCURRENCY:-256}"
frames="${VELOAUTH_BENCHMARK_FRAMES:-1000000}"
warmup="${VELOAUTH_BENCHMARK_WARMUP:-200000}"

if command -v mvnd >/dev/null 2>&1; then
  maven_command=(mvnd)
elif [[ -x "${project_dir}/mvnw" ]]; then
  maven_command=("${project_dir}/mvnw")
elif command -v mvn >/dev/null 2>&1; then
  maven_command=(mvn)
else
  echo "Maven, mvnd or ./mvnw is required" >&2
  exit 1
fi

"${maven_command[@]}" -f "${project_dir}/pom.xml" test \
  -Dtest=BoundedNetworkServerPerformanceTest,EmbeddedLimboLoadTest \
  -Dveloauth.benchmark=true \
  -Dveloauth.benchmark.connections="${connections}" \
  -Dveloauth.benchmark.concurrency="${concurrency}" \
  -Dveloauth.benchmark.operations="${frames}" \
  -Dveloauth.benchmark.warmup="${warmup}"
