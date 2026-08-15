#!/usr/bin/env bash
# Prints the Maven project version as `version=<X.Y.Z>`.
#
# Parses pom.xml offline — deliberately without invoking Maven or the wrapper, so release
# tooling cannot be influenced by a plugin, a profile or a populated local repository. The
# same strict single-direct-release-version contract as scripts/verify-release-identity.sh
# is enforced here, and any deviation fails closed.
#
# The `version=` prefix makes the output directly appendable to $GITHUB_OUTPUT.
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd -P)"

fail() {
  echo "$1" >&2
  exit 1
}

command -v python3 >/dev/null 2>&1 || fail "python3 is required to read the Maven project version"

PROJECT_VERSION="$(python3 - "${PROJECT_DIR}/pom.xml" <<'PY'
import re
import sys
import xml.etree.ElementTree as ElementTree

try:
    root = ElementTree.parse(sys.argv[1]).getroot()
except (OSError, ElementTree.ParseError) as error:
    print(f"Unable to read Maven project version: {error}", file=sys.stderr)
    raise SystemExit(1)

namespace = root.tag.rpartition("}")[0] + "}" if "}" in root.tag else ""
if root.tag != f"{namespace}project":
    print("Maven project root element must be <project>", file=sys.stderr)
    raise SystemExit(1)

versions = [
    (child.text or "").strip()
    for child in root
    if child.tag == f"{namespace}version"
]
if len(versions) != 1 or re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", versions[0]) is None:
    print("Maven project must contain exactly one direct release version", file=sys.stderr)
    raise SystemExit(1)

print(versions[0])
PY
)" || fail "Failed to parse the Maven project version"

[[ "${PROJECT_VERSION}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] \
  || fail "Maven project version is not a release version: ${PROJECT_VERSION:-<empty>}"

printf 'version=%s\n' "${PROJECT_VERSION}"
