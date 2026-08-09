#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
EXPECTED_MCPROTOCOLLIB_SHA256="07ec18ba92c8b4041286eeff2470e08257fd1f383881515cba4a0a9bf6fa98c1"
EXPECTED_VIAVERSION_SHA256="a4dd9f63257ed923f73a64ecece31010acd04247db12855383172e1226912b3e"

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

evaluate_maven_expression() {
  "${MAVEN[@]}" -f "${PROJECT_DIR}/pom.xml" help:evaluate \
    -Dstyle.color=never -DforceStdout -Dexpression="$1" \
    | awk 'NF && $0 !~ /^\[/ { value=$0 } END { print value }'
}

MCPROTOCOLLIB_VERSION="$(evaluate_maven_expression mcprotocollib.version)"
CONFIGURED_MCPROTOCOLLIB_SHA256="$(evaluate_maven_expression mcprotocollib.sha256)"
VIAVERSION_DEPENDENCY_VERSION="$(evaluate_maven_expression viaversion.runtime.dependency-version)"
VIAVERSION_VERSION="$(evaluate_maven_expression viaversion.runtime.version)"
CONFIGURED_VIAVERSION_SHA256="$(evaluate_maven_expression viaversion.runtime.sha256)"
LOCAL_REPOSITORY="$(evaluate_maven_expression settings.localRepository)"

if [[ "${CONFIGURED_MCPROTOCOLLIB_SHA256}" != "${EXPECTED_MCPROTOCOLLIB_SHA256}" ]]; then
  echo "pom.xml MCProtocolLib checksum does not match the independently audited script value" >&2
  exit 1
fi

if [[ "${CONFIGURED_VIAVERSION_SHA256}" != "${EXPECTED_VIAVERSION_SHA256}" ]]; then
  echo "pom.xml ViaVersion checksum does not match the independently audited script value" >&2
  exit 1
fi

"${MAVEN[@]}" -q -f "${PROJECT_DIR}/pom.xml" dependency:get \
  -Dartifact="org.geysermc.mcprotocollib:protocol:${MCPROTOCOLLIB_VERSION}" \
  -Dtransitive=false
"${MAVEN[@]}" -q -f "${PROJECT_DIR}/pom.xml" dependency:get \
  -Dartifact="com.viaversion:viaversion-common:${VIAVERSION_DEPENDENCY_VERSION}" \
  -Dtransitive=false

MCPROTOCOLLIB_JAR="$(find \
  "${LOCAL_REPOSITORY}/org/geysermc/mcprotocollib/protocol" \
  -maxdepth 2 -type f -name "protocol-${MCPROTOCOLLIB_VERSION}.jar" -print -quit)"
if [[ -z "${MCPROTOCOLLIB_JAR}" ]]; then
  echo "Pinned MCProtocolLib artifact was not found in the local Maven repository" >&2
  exit 1
fi

VIAVERSION_JAR="${LOCAL_REPOSITORY}/com/viaversion/viaversion-common/${VIAVERSION_DEPENDENCY_VERSION}/viaversion-common-${VIAVERSION_DEPENDENCY_VERSION}.jar"
if [[ ! -f "${VIAVERSION_JAR}" ]]; then
  echo "Pinned ViaVersion runtime artifact was not found in the local Maven repository" >&2
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

ACTUAL_MCPROTOCOLLIB_SHA256="$(sha256_file "${MCPROTOCOLLIB_JAR}")"
ACTUAL_VIAVERSION_SHA256="$(sha256_file "${VIAVERSION_JAR}")"

if [[ "${ACTUAL_MCPROTOCOLLIB_SHA256}" != "${EXPECTED_MCPROTOCOLLIB_SHA256}" ]]; then
  echo "MCProtocolLib checksum mismatch" >&2
  echo "Expected: ${EXPECTED_MCPROTOCOLLIB_SHA256}" >&2
  echo "Actual:   ${ACTUAL_MCPROTOCOLLIB_SHA256}" >&2
  exit 1
fi

if [[ "${ACTUAL_VIAVERSION_SHA256}" != "${EXPECTED_VIAVERSION_SHA256}" ]]; then
  echo "ViaVersion runtime checksum mismatch" >&2
  echo "Expected: ${EXPECTED_VIAVERSION_SHA256}" >&2
  echo "Actual:   ${ACTUAL_VIAVERSION_SHA256}" >&2
  exit 1
fi

echo "Verified MCProtocolLib ${MCPROTOCOLLIB_VERSION} SHA-256: ${ACTUAL_MCPROTOCOLLIB_SHA256}"
echo "Verified ViaVersion ${VIAVERSION_VERSION} SHA-256: ${ACTUAL_VIAVERSION_SHA256}"
