#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

export VELOAUTH_VELOCITY_URL="https://github.com/GemstoneGG/Velocity-CTD/releases/download/build-355/velocity-ctd-fatjar-4.1.0-SNAPSHOT-355.jar"
export VELOAUTH_VELOCITY_SHA256="85d1492b815bc819e7fa263edde9c31f8cc9f837a6d0ed105825462dd2f2ad6f"
export VELOAUTH_VELOCITY_LABEL="Velocity-CTD build 355"
export VELOAUTH_TEST_FORWARDING_MODE="modern"
export VELOAUTH_TEST_RUNTIME_UPDATE="${VELOAUTH_TEST_RUNTIME_UPDATE:-false}"

exec "${SCRIPT_DIR}/test-velocity-embedded.sh"
