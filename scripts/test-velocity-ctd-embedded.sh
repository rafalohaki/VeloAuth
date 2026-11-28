#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
CTD_JAVA_HOME="${VELOAUTH_CTD_JAVA25_HOME:-}"
REQUIRE_PINNED_CTD_JAVA="${VELOAUTH_CTD_REQUIRE_PINNED_JAVA25:-false}"

validate_ctd_java() {
  local candidate=$1
  local metadata java_version java_runtime java_vendor java_vendor_version
  [[ "${candidate}" == /* && -d "${candidate}" && -x "${candidate}/bin/java" ]] \
    || return 1
  metadata="$("${candidate}/bin/java" -XshowSettings:properties -version 2>&1)" \
    || return 1
  java_version="$(printf '%s\n' "${metadata}" \
    | sed -n 's/^[[:space:]]*java\.version = //p' | head -n 1)"
  java_runtime="$(printf '%s\n' "${metadata}" \
    | sed -n 's/^[[:space:]]*java\.runtime\.version = //p' | head -n 1)"
  java_vendor="$(printf '%s\n' "${metadata}" \
    | sed -n 's/^[[:space:]]*java\.vendor = //p' | head -n 1)"
  java_vendor_version="$(printf '%s\n' "${metadata}" \
    | sed -n 's/^[[:space:]]*java\.vendor\.version = //p' | head -n 1)"
  [[ "${java_version}" == 25.0.4 \
      && ( "${java_runtime}" == 25.0.4+7 || "${java_runtime}" == 25.0.4+7-LTS ) \
      && "${java_vendor}" == "Eclipse Adoptium" \
      && "${java_vendor_version}" == "Temurin-25.0.4+7" ]]
}

case "${REQUIRE_PINNED_CTD_JAVA}" in
  true)
    [[ -n "${CTD_JAVA_HOME}" ]] \
      || {
        echo "Velocity-CTD smoke requires VELOAUTH_CTD_JAVA25_HOME" >&2
        exit 1
      }
    ;;
  false) ;;
  *)
    echo "VELOAUTH_CTD_REQUIRE_PINNED_JAVA25 must be true or false" >&2
    exit 1
    ;;
esac
if [[ -n "${CTD_JAVA_HOME}" ]]; then
  validate_ctd_java "${CTD_JAVA_HOME}" \
    || {
      echo "VELOAUTH_CTD_JAVA25_HOME must be exact Temurin 25.0.4+7" >&2
      exit 1
    }
  export VELOAUTH_SMOKE_JAVA="${CTD_JAVA_HOME}/bin/java"
fi

export VELOAUTH_VELOCITY_URL="https://github.com/GemstoneGG/Velocity-CTD/releases/download/build-425/velocity-ctd-fatjar-4.3.2-SNAPSHOT-425.jar"
export VELOAUTH_VELOCITY_SHA256="5848bb5bf9835443620a5f7f87a1e9e27d1c282943bcffdc6d53957caede84e9"
export VELOAUTH_VELOCITY_LABEL="Velocity-CTD build 425"
export VELOAUTH_TEST_FORWARDING_MODE="modern"

exec "${SCRIPT_DIR}/test-velocity-embedded.sh"
